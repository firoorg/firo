#include "config/bitcoin-config.h"

#include <../../test/fixtures.h>
#include "../../chainparams.h"
#include "../../policy/policy.h"
#include "../../spark/state.h"
#include "../coincontrol.h"
#include "../wallet.h"
#include "../../spark/sparkwallet.h"
#include "../../streams.h"
#ifdef USE_SQLITE
#include "../../init.h"
#include "../../utilstrencodings.h"
#include "../sqlite.h"

#include <sqlite3.h>
#endif
#include "../../validation.h"
#include "../../validationinterface.h"

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <limits>

#ifdef USE_SQLITE
#include <atomic>
#endif

static std::vector<unsigned char> random_char_vector()
{                                                    
    Scalar temp;
    temp.randomize();
    std::vector<unsigned char> result;
    result.resize(spark::SCALAR_ENCODING);
    temp.serialize(result.data());
    return result;
}

CBlock GetCBlock(CBlockIndex const *blockIdx)
{
    CBlock block;
    if (!ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus())) {
        throw std::invalid_argument("No block index data");
    }

    return block;
}

void ExtractSpend(CTransaction const &tx,                                                 
     std::vector<spark::Coin>& coins,
     std::vector<GroupElement>& lTags) {

     if (tx.vin[0].scriptSig.IsSparkSpend()) {
         coins.clear();
         coins =  spark::GetSparkMintCoins(tx);
         lTags.clear();
         lTags =  spark::GetSparkUsedTags(tx);
     }
}

static void ReloadSparkWallet()
{
    pwalletMain->sparkWallet.reset();
    pwalletMain->sparkWallet = std::make_unique<CSparkWallet>(*pwalletMain);
}

#ifdef USE_SQLITE
extern std::atomic<bool> fRequestShutdown;

namespace
{
class InstallDiversifierFailureExecutor final : public SQLiteStatementExecutor
{
private:
    const std::string m_serialized_key_hex;
    bool m_installed{false};

public:
    explicit InstallDiversifierFailureExecutor(
        std::string serializedKeyHex)
        : m_serialized_key_hex(std::move(serializedKeyHex))
    {
    }

    int Execute(sqlite3* database, const char* statement) override
    {
        if (!m_installed &&
            std::string(statement) == "BEGIN TRANSACTION") {
            const std::string trigger = strprintf(
                "CREATE TEMP TRIGGER reject_spark_diversifier "
                "BEFORE INSERT ON main WHEN NEW.key = X'%s' BEGIN "
                "SELECT RAISE(FAIL, 'injected Spark diversifier failure'); END",
                m_serialized_key_hex);
            const int result = SQLiteStatementExecutor::Execute(
                database,
                trigger.c_str());
            if (result != SQLITE_OK) {
                return result;
            }
            m_installed = true;
        }
        return SQLiteStatementExecutor::Execute(
            database,
            statement);
    }
};

class CommitThenFailSQLiteExecutor final : public SQLiteStatementExecutor
{
public:
    int Execute(sqlite3* database, const char* statement) override
    {
        const int result =
            SQLiteStatementExecutor::Execute(database, statement);
        if (result == SQLITE_OK &&
            std::string(statement) == "COMMIT TRANSACTION") {
            return SQLITE_IOERR;
        }
        return result;
    }
};

class ShutdownRequestReset
{
private:
    const bool m_previous;

public:
    ShutdownRequestReset()
        : m_previous(fRequestShutdown.exchange(false))
    {
    }

    ~ShutdownRequestReset()
    {
        fRequestShutdown.store(m_previous);
    }
};

std::unique_ptr<CWallet> MakeSQLiteSparkTestWallet(
    const std::string& filename)
{
    DatabaseOptions options;
    options.require_create = true;
    options.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status;
    std::string error;
    std::unique_ptr<WalletDatabase> database =
        MakeSQLiteDatabase(filename, options, status, error);
    if (!database) {
        throw std::runtime_error(
            "Unable to create SQLite Spark test wallet: " + error);
    }

    auto wallet = std::make_unique<CWallet>(std::move(database));
    const CPubKey masterKey = wallet->GenerateNewHDMasterKey();
    if (!wallet->SetHDMasterKey(
            masterKey,
            CHDChain().VERSION_WITH_BIP44)) {
        throw std::runtime_error(
            "Unable to initialize SQLite Spark test wallet");
    }
    return wallet;
}

void InstallDiversifierFailure(WalletDatabase& database)
{
    CDataStream key(SER_DISK, CLIENT_VERSION);
    key << std::string("div");
    std::unique_ptr<DatabaseBatch> batch = database.MakeBatch();
    if (!SetSQLiteStatementExecutorForTesting(
            *batch,
            std::make_unique<InstallDiversifierFailureExecutor>(
                HexStr(key.begin(), key.end()))) ||
        !batch->TxnBegin() ||
        !batch->TxnAbort()) {
        throw std::runtime_error(
            "Unable to install SQLite Spark failure trigger");
    }
}

void CheckSameSparkAddress(
    const spark::Address& first,
    const spark::Address& second)
{
    BOOST_CHECK(first.get_d() == second.get_d());
    BOOST_CHECK(first.get_Q1() == second.get_Q1());
    BOOST_CHECK(first.get_Q2() == second.get_Q2());
}
} // namespace
#endif

BOOST_FIXTURE_TEST_SUITE(spark_wallet_tests, SparkTestingSetup)

#ifdef USE_SQLITE
BOOST_AUTO_TEST_CASE(sqlite_initialization_state_contract)
{
    const spark::Params* params = spark::Params::get_default();

    {
        auto wallet = MakeSQLiteSparkTestWallet(
            "spark_sqlite_success.dat");
        std::string firstViewKey;
        spark::Address firstDefaultAddress(params);
        {
            CSparkWallet sparkWallet(*wallet);
            firstViewKey = wallet->GetSparkViewKeyStr();
            firstDefaultAddress = sparkWallet.getDefaultAddress();
            const auto addresses = sparkWallet.getAllAddresses();
            BOOST_REQUIRE_EQUAL(addresses.size(), 1U);
            BOOST_CHECK(addresses.count(0) == 1);
        }

        {
            CSparkWallet reloaded(*wallet);
            BOOST_CHECK_EQUAL(
                wallet->GetSparkViewKeyStr(),
                firstViewKey);
            CheckSameSparkAddress(
                reloaded.getDefaultAddress(),
                firstDefaultAddress);
            const auto addresses = reloaded.getAllAddresses();
            BOOST_REQUIRE_EQUAL(addresses.size(), 1U);
            BOOST_CHECK(addresses.count(0) == 1);
        }

        CWalletDB walletdb(wallet->GetDatabase());
        spark::FullViewKey fullViewKey(params);
        int32_t diversifier = -1;
        BOOST_CHECK(
            walletdb.readFullViewKeyWithStatus(fullViewKey) ==
            DatabaseReadStatus::SUCCESS);
        BOOST_CHECK(
            walletdb.readDiversifierWithStatus(diversifier) ==
            DatabaseReadStatus::SUCCESS);
        BOOST_CHECK_EQUAL(diversifier, 0);
    }

    {
        auto wallet = MakeSQLiteSparkTestWallet(
            "spark_sqlite_full_view_key_only.dat");
        {
            CSparkWallet initialized(*wallet);
        }
        {
            std::unique_ptr<DatabaseBatch> batch =
                wallet->GetDatabase().MakeBatch();
            BOOST_REQUIRE(batch->Erase(std::string("div")));
        }

        BOOST_CHECK_THROW(
            std::make_unique<CSparkWallet>(*wallet),
            std::runtime_error);
        CWalletDB walletdb(wallet->GetDatabase());
        spark::FullViewKey fullViewKey(params);
        int32_t diversifier = -1;
        BOOST_CHECK(
            walletdb.readFullViewKeyWithStatus(fullViewKey) ==
            DatabaseReadStatus::SUCCESS);
        BOOST_CHECK(
            walletdb.readDiversifierWithStatus(diversifier) ==
            DatabaseReadStatus::NOT_FOUND);
    }

    {
        auto wallet = MakeSQLiteSparkTestWallet(
            "spark_sqlite_diversifier_only.dat");
        {
            CSparkWallet initialized(*wallet);
        }
        {
            std::unique_ptr<DatabaseBatch> batch =
                wallet->GetDatabase().MakeBatch();
            BOOST_REQUIRE(
                batch->Erase(std::string("fullViewKey")));
        }

        BOOST_CHECK_THROW(
            std::make_unique<CSparkWallet>(*wallet),
            std::runtime_error);
        BOOST_CHECK_THROW(
            wallet->GetSparkViewKey(),
            std::runtime_error);
        CWalletDB walletdb(wallet->GetDatabase());
        spark::FullViewKey fullViewKey(params);
        int32_t diversifier = -1;
        BOOST_CHECK(
            walletdb.readFullViewKeyWithStatus(fullViewKey) ==
            DatabaseReadStatus::NOT_FOUND);
        BOOST_CHECK(
            walletdb.readDiversifierWithStatus(diversifier) ==
            DatabaseReadStatus::SUCCESS);
        BOOST_CHECK_EQUAL(diversifier, 0);
    }

    {
        auto wallet = MakeSQLiteSparkTestWallet(
            "spark_sqlite_corrupt_full_view_key.dat");
        {
            CSparkWallet initialized(*wallet);
        }
        {
            std::unique_ptr<DatabaseBatch> batch =
                wallet->GetDatabase().MakeBatch();
            BOOST_REQUIRE(batch->Write(
                std::string("fullViewKey"),
                uint8_t{1}));
        }

        BOOST_CHECK_THROW(
            std::make_unique<CSparkWallet>(*wallet),
            std::runtime_error);
        BOOST_CHECK_THROW(
            wallet->GetSparkViewKey(),
            std::runtime_error);
        CWalletDB walletdb(wallet->GetDatabase());
        spark::FullViewKey fullViewKey(params);
        int32_t diversifier = -1;
        BOOST_CHECK(
            walletdb.readFullViewKeyWithStatus(fullViewKey) ==
            DatabaseReadStatus::CORRUPT);
        BOOST_CHECK(
            walletdb.readDiversifierWithStatus(diversifier) ==
            DatabaseReadStatus::SUCCESS);
        BOOST_CHECK_EQUAL(diversifier, 0);
    }
}

BOOST_AUTO_TEST_CASE(sqlite_initialization_write_is_atomic)
{
    auto wallet = MakeSQLiteSparkTestWallet(
        "spark_sqlite_atomic_initialization.dat");
    InstallDiversifierFailure(wallet->GetDatabase());

    BOOST_CHECK_THROW(
        std::make_unique<CSparkWallet>(*wallet),
        std::runtime_error);

    CWalletDB walletdb(wallet->GetDatabase());
    spark::FullViewKey fullViewKey(spark::Params::get_default());
    int32_t diversifier = -1;
    BOOST_CHECK(
        walletdb.readFullViewKeyWithStatus(fullViewKey) ==
        DatabaseReadStatus::NOT_FOUND);
    BOOST_CHECK(
        walletdb.readDiversifierWithStatus(diversifier) ==
        DatabaseReadStatus::NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(sqlite_address_persistence_precedes_publication)
{
    auto wallet = MakeSQLiteSparkTestWallet(
        "spark_sqlite_address_persistence.dat");
    CSparkWallet sparkWallet(*wallet);
    const auto addressesBefore = sparkWallet.getAllAddresses();
    BOOST_REQUIRE_EQUAL(addressesBefore.size(), 1U);
    BOOST_REQUIRE(addressesBefore.count(0) == 1);

    InstallDiversifierFailure(wallet->GetDatabase());
    BOOST_CHECK_THROW(
        sparkWallet.generateNewAddress(),
        std::runtime_error);

    const auto addressesAfter = sparkWallet.getAllAddresses();
    BOOST_REQUIRE_EQUAL(
        addressesAfter.size(),
        addressesBefore.size());
    BOOST_REQUIRE(addressesAfter.count(0) == 1);
    CheckSameSparkAddress(
        addressesAfter.at(0),
        addressesBefore.at(0));
    CWalletDB walletdb(wallet->GetDatabase());
    int32_t diversifier = -1;
    BOOST_REQUIRE(
        walletdb.readDiversifierWithStatus(diversifier) ==
        DatabaseReadStatus::SUCCESS);
    BOOST_CHECK_EQUAL(diversifier, 0);
}

BOOST_AUTO_TEST_CASE(sqlite_backend_failure_does_not_initialize_spark)
{
    ShutdownRequestReset shutdownReset;
    BOOST_REQUIRE(!ShutdownRequested());
    const std::string filename{
        "spark_sqlite_backend_failure.dat"};
    auto wallet = MakeSQLiteSparkTestWallet(filename);
    std::unique_ptr<DatabaseBatch> batch =
        wallet->GetDatabase().MakeBatch();
    BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
        *batch,
        std::make_unique<CommitThenFailSQLiteExecutor>()));
    BOOST_CHECK_THROW(
        batch->Write(
            std::string("failure-probe"),
            std::string("applied-before-error")),
        std::runtime_error);
    BOOST_CHECK(ShutdownRequested());
    BOOST_CHECK_THROW(
        std::make_unique<CSparkWallet>(*wallet),
        std::runtime_error);
    batch.reset();
    wallet.reset();

    DatabaseOptions options;
    options.require_existing = true;
    options.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status;
    std::string error;
    std::unique_ptr<WalletDatabase> reopened =
        MakeSQLiteDatabase(filename, options, status, error);
    BOOST_REQUIRE(reopened);
    CWalletDB walletdb(*reopened);
    spark::FullViewKey fullViewKey(
        spark::Params::get_default());
    int32_t diversifier = -1;
    BOOST_CHECK(
        walletdb.readFullViewKeyWithStatus(fullViewKey) ==
        DatabaseReadStatus::NOT_FOUND);
    BOOST_CHECK(
        walletdb.readDiversifierWithStatus(diversifier) ==
        DatabaseReadStatus::NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(sqlite_reload_preserves_upstream_spark_checks)
{
    auto wallet = MakeSQLiteSparkTestWallet("spark_sqlite_reload_checks.dat");
    wallet->sparkWallet = std::make_unique<CSparkWallet>(*wallet);
    CMutableTransaction parent;
    parent.vin.emplace_back(COutPoint(uint256S("02"), 0));
    parent.vout.emplace_back(0, CScript() << OP_RETURN);
    const CTransaction transaction(parent);
    const auto serialContext = spark::getSerialContext(transaction);
    const uint256 parentHash = transaction.GetHash();
    Scalar mintNonce;
    mintNonce.randomize();
    Scalar spendNonce;
    spendNonce.randomize();
    const auto address = wallet->sparkWallet->getDefaultAddress();
    const spark::Coin mint(params, spark::COIN_TYPE_MINT, mintNonce,
        address, COIN, "SQLite reload mint", serialContext);
    const spark::Coin smint(params, spark::COIN_TYPE_SPEND, spendNonce,
        address, 2 * COIN, "SQLite reload smint", serialContext);
    {
        CWalletDB walletdb(wallet->GetDatabase());
        wallet->sparkWallet->UpdateMintState({mint, smint}, parentHash, walletdb);
        BOOST_REQUIRE_EQUAL(walletdb.ListSparkMints().size(), 2U);
    }

    auto reload = [&]() {
        wallet->sparkWallet.reset();
        wallet->sparkWallet = std::make_unique<CSparkWallet>(*wallet);
        wallet->sparkWallet->WaitForPendingTasks();
    };
    // A missing SMint parent is retained on disk but excluded from balances.
    reload();
    BOOST_CHECK_EQUAL(wallet->sparkWallet->getFullBalance(), COIN);
    BOOST_REQUIRE_EQUAL(wallet->sparkWallet->getMintMap().size(), 1U);
    BOOST_CHECK(wallet->sparkWallet->validateLookupIndexes());
    {
        CWalletDB walletdb(wallet->GetDatabase());
        BOOST_CHECK_EQUAL(walletdb.ListSparkMints().size(), 2U);
    }

    // A known parent that is not a spend makes the saved SMint invalid.
    BOOST_REQUIRE(wallet->AddToWallet(CWalletTx(
        wallet.get(), MakeTransactionRef(transaction))));
    reload();
    BOOST_CHECK_EQUAL(wallet->sparkWallet->getFullBalance(), COIN);
    BOOST_CHECK(wallet->sparkWallet->validateLookupIndexes());
    {
        CWalletDB walletdb(wallet->GetDatabase());
        BOOST_CHECK_EQUAL(walletdb.ListSparkMints().size(), 1U);
    }
}

BOOST_AUTO_TEST_CASE(sqlite_failed_initialization_relocks_wallet)
{
    const SecureString passphrase{
        "Spark SQLite relock test passphrase"};
    auto wallet = MakeSQLiteSparkTestWallet(
        "spark_sqlite_relock.dat");
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet->IsLocked());
    InstallDiversifierFailure(wallet->GetDatabase());

    bool unlockRequested = false;
    boost::signals2::scoped_connection unlockConnection(
        UnlockWallet.connect([&](CWallet* requestedWallet) {
            if (requestedWallet != wallet.get() ||
                !requestedWallet->Unlock(passphrase)) {
                throw std::runtime_error(
                    "Unable to unlock SQLite Spark test wallet");
            }
            unlockRequested = true;
        }));
    BOOST_CHECK_THROW(
        std::make_unique<CSparkWallet>(*wallet),
        std::runtime_error);
    BOOST_CHECK(unlockRequested);
    BOOST_CHECK(wallet->IsLocked());

    CWalletDB walletdb(wallet->GetDatabase());
    spark::FullViewKey fullViewKey(
        spark::Params::get_default());
    int32_t diversifier = -1;
    BOOST_CHECK(
        walletdb.readFullViewKeyWithStatus(fullViewKey) ==
        DatabaseReadStatus::NOT_FOUND);
    BOOST_CHECK(
        walletdb.readDiversifierWithStatus(diversifier) ==
        DatabaseReadStatus::NOT_FOUND);
}
#endif


BOOST_AUTO_TEST_CASE(standalone_smint_has_no_wallet_provenance)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(uint256S("01"), 0));

    const std::vector<unsigned char> serialContext =
        spark::getSerialContext(CTransaction(tx));
    BOOST_REQUIRE(!serialContext.empty());

    Scalar k;
    k.randomize();
    spark::Coin coin(
        params,
        spark::COIN_TYPE_SPEND,
        k,
        pwalletMain->sparkWallet->getDefaultAddress(),
        100 * COIN,
        "standalone smint regression",
        serialContext);

    CDataStream encoded(SER_NETWORK, PROTOCOL_VERSION);
    encoded << coin;

    CScript smint;
    smint << OP_SPARKSMINT;
    smint.insert(smint.end(), encoded.begin(), encoded.end());
    tx.vout.emplace_back(0, smint);

    const CTransaction standalone(tx);
    BOOST_REQUIRE(!standalone.IsSparkTransaction());

    std::string reason;
    BOOST_CHECK(!IsStandardTx(standalone, reason));
    BOOST_CHECK_EQUAL(reason, "spark-smint-without-spend");
    BOOST_CHECK_EQUAL(
        pwalletMain->IsMine(standalone.vout[0], standalone),
        ISMINE_NO);
    BOOST_CHECK_EQUAL(
        pwalletMain->GetCredit(
            standalone.vout[0], standalone, ISMINE_SPENDABLE),
        0);

    spark::SpendKey foreignSpendKey(params);
    spark::FullViewKey foreignViewKey(foreignSpendKey);
    spark::IncomingViewKey foreignIncomingViewKey(foreignViewKey);
    spark::MintedCoinData mintData;
    mintData.address = spark::Address(foreignIncomingViewKey, 0);
    mintData.v = COIN;
    const auto recipients = CSparkWallet::CreateSparkMintRecipients(
        {mintData}, serialContext, true);
    BOOST_REQUIRE_EQUAL(recipients.size(), 1U);

    CMutableTransaction mixed(tx);
    mixed.vout.emplace_back(
        recipients.front().nAmount, recipients.front().scriptPubKey);
    const CTransaction mixedTransaction(mixed);
    BOOST_REQUIRE(mixedTransaction.IsSparkTransaction());
    BOOST_REQUIRE(!mixedTransaction.IsSparkSpend());
    reason.clear();
    BOOST_CHECK(!IsStandardTx(mixedTransaction, reason));
    BOOST_CHECK_EQUAL(reason, "spark-smint-without-spend");

    CValidationState validationState;
    spark::CSparkTxInfo info;
    BOOST_REQUIRE(CheckTransaction(
        mixedTransaction, validationState, true, mixedTransaction.GetHash(),
        false, ::Params().GetConsensus().nSparkChaumV2StartBlock,
        false, true, &info));
    BOOST_REQUIRE_EQUAL(info.mints.size(), 1U);

    const auto mixedCoins = spark::GetSparkMintCoins(mixedTransaction);
    BOOST_REQUIRE_EQUAL(mixedCoins.size(), 1U);
    BOOST_CHECK(
        mixedCoins.front().getHash() == info.mints.front().getHash());

    CBlock mixedBlock;
    mixedBlock.vtx.push_back(MakeTransactionRef(mixedTransaction));
    COutPoint outPoint;
    BOOST_CHECK(!spark::GetOutPointFromBlock(outPoint, coin, mixedBlock));
    BOOST_REQUIRE(spark::GetOutPointFromBlock(
        outPoint, info.mints.front(), mixedBlock));
    BOOST_CHECK(outPoint == COutPoint(mixedTransaction.GetHash(), 1));
    BOOST_CHECK(!pwalletMain->IsMine(mixedTransaction));

    {
        LOCK(pwalletMain->cs_wallet);
        BOOST_CHECK(!pwalletMain->AddToWalletIfInvolvingMe(
            standalone, nullptr, -1, false));
        BOOST_CHECK(!pwalletMain->mapWallet.count(standalone.GetHash()));
    }

    // Reproduce metadata written by an older wallet for the mixed transaction.
    {
        CWalletDB walletdb(pwalletMain->GetDatabase());
        pwalletMain->sparkWallet->UpdateMintState(
            {coin}, mixedTransaction.GetHash(), walletdb);
        BOOST_REQUIRE_EQUAL(walletdb.ListSparkMints().size(), 1U);
    }
    BOOST_CHECK_EQUAL(pwalletMain->sparkWallet->getUnconfirmedBalance(), 100 * COIN);

    // Missing parents must not make saved metadata authoritative. Keep the
    // database record for recovery, but exclude it from balances and lookups.
    for (int height : {-1, 1}) {
        CWalletDB walletdb(pwalletMain->GetDatabase());
        auto savedMints = walletdb.ListSparkMints();
        BOOST_REQUIRE_EQUAL(savedMints.size(), 1U);
        auto& savedMint = *savedMints.begin();
        savedMint.second.nHeight = height;
        BOOST_REQUIRE(walletdb.WriteSparkMint(savedMint.first, savedMint.second));

        ReloadSparkWallet();
        BOOST_CHECK_EQUAL(pwalletMain->sparkWallet->getUnconfirmedBalance(), 0);
        BOOST_CHECK_EQUAL(pwalletMain->sparkWallet->getAvailableBalance(), 0);
        BOOST_CHECK(pwalletMain->sparkWallet->getMintMap().empty());
        BOOST_CHECK(pwalletMain->sparkWallet->validateLookupIndexes());
        BOOST_CHECK_EQUAL(walletdb.ListSparkMints().size(), 1U);
    }

    // Once the non-spend parent is known, remove the invalid record from disk.
    BOOST_REQUIRE(pwalletMain->AddToWallet(CWalletTx(
        pwalletMain, MakeTransactionRef(mixedTransaction))));
    ReloadSparkWallet();
    BOOST_CHECK_EQUAL(pwalletMain->sparkWallet->getUnconfirmedBalance(), 0);
    CWalletDB walletdb(pwalletMain->GetDatabase());
    BOOST_CHECK(walletdb.ListSparkMints().empty());
}

BOOST_AUTO_TEST_CASE(create_mint_recipient)
{
    const uint64_t v = 1;
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    auto recipients = CSparkWallet::CreateSparkMintRecipients(mintedCoins, random_char_vector(), true);

    BOOST_CHECK(recipients[0].scriptPubKey.IsSparkMint());
    BOOST_CHECK_EQUAL(recipients[0].nAmount, v);
}

BOOST_AUTO_TEST_CASE(reject_out_of_range_mint_amounts)
{
    spark::MintedCoinData data;
    data.address = pwalletMain->sparkWallet->getDefaultAddress();

    const auto checkRejected = [&](const std::vector<spark::MintedCoinData>& outputs, bool fSplit = false) {
        std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
        BOOST_CHECK_EQUAL(pwalletMain->MintAndStoreSpark(outputs, wtxAndFee, false, fSplit),
            "Spark mint amount out of range");

        CAmount fee = 0;
        std::list<CReserveKey> reservekeys;
        int changePos = -1;
        std::string error;
        BOOST_CHECK(!pwalletMain->CreateSparkMintTransactions(outputs, wtxAndFee, fee,
            reservekeys, changePos, false, error, fSplit, nullptr));
        BOOST_CHECK_EQUAL(error, "Spark mint amount out of range");
        BOOST_CHECK(wtxAndFee.empty());
    };

    data.v = std::numeric_limits<uint64_t>::max();
    checkRejected({data});

    data.v = MAX_MONEY;
    spark::MintedCoinData extra = data;
    extra.v = 1;
    checkRejected({data, extra});
    checkRejected({data, extra}, true);
}

BOOST_AUTO_TEST_CASE(mint_and_store_spark)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;

    const uint64_t v = 1;
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    const CFeeRate savedFee = payTxFee;
    payTxFee = CFeeRate(MAX_MONEY);
    BOOST_CHECK_EQUAL(pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true),
        "Spark mint fee out of range");
    payTxFee = savedFee;
    BOOST_CHECK(wtxAndFee.empty());

    CCoinControl coinControl;
    coinControl.nMinimumTotalFee = std::numeric_limits<CAmount>::max();
    CAmount fee = 0;
    std::list<CReserveKey> reservekeys;
    int changePos = -1;
    std::string error;
    BOOST_CHECK(!pwalletMain->CreateSparkMintTransactions(mintedCoins, wtxAndFee, fee,
        reservekeys, changePos, false, error, true, &coinControl));
    BOOST_CHECK_EQUAL(error, "Spark mint fee out of range");
    BOOST_CHECK(wtxAndFee.empty());

    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL(result, "");

    size_t mintAmount = 0;
    for (const auto& wtx : wtxAndFee) {
        auto tx = wtx.first.tx.get();

        BOOST_CHECK(tx->IsSparkMint());
        BOOST_CHECK(tx->IsSparkTransaction());

        for (const auto& out : tx->vout) {
            if (out.scriptPubKey.IsSparkMint()) {
                mintAmount += out.nValue;
            }
        }
        CMutableTransaction mtx(*tx);
        BOOST_CHECK(GenerateBlock({mtx}));
    }

    BOOST_CHECK_EQUAL(data.v, mintAmount);

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(mint_subtract_fee)
{
    pwalletMain->SetBroadcastTransactions(true);
    uint160 externalKey;
    GetRandBytes(externalKey.begin(), externalKey.size());
    CScript externalScript = GetScriptForDestination(CKeyID(externalKey));
    GenerateBlocks(1001, &externalScript);
    GenerateBlocks(1);
    GenerateBlocks(100, &externalScript);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;

    const uint64_t v = pwalletMain->GetBalance();
    BOOST_REQUIRE_GT(v, 0);
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    const CFeeRate savedFee = payTxFee;
    payTxFee = CFeeRate(1000);
    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, true, true);
    payTxFee = savedFee;
    BOOST_CHECK_EQUAL(result, "");

    size_t mintAmount = 0;
    size_t fee = 0;
    for (const auto& wtx : wtxAndFee) {
        auto tx = wtx.first.tx.get();

        BOOST_CHECK(tx->IsSparkMint());
        BOOST_CHECK(tx->IsSparkTransaction());

        for (const auto& out : tx->vout) {
            if (out.scriptPubKey.IsSparkMint()) {
                mintAmount += out.nValue;
            }
        }
        CMutableTransaction mtx(*tx);
        BOOST_CHECK(GenerateBlock({mtx}));
        fee += wtx.second;
    }

    BOOST_CHECK_GT(fee, 0);
    BOOST_CHECK_EQUAL(data.v, mintAmount + fee);

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(list_spark_mints)
{
    GenerateBlocks(1001);
    std::vector<CAmount> confirmedAmounts = {1, 2 * COIN};
    std::vector<CAmount> unconfirmedAmounts = {10 * COIN};
    std::vector<CAmount> allAmounts(confirmedAmounts);
    allAmounts.insert(allAmounts.end(), unconfirmedAmounts.begin(), unconfirmedAmounts.end());

    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints(allAmounts, txs);
    std::vector<CMutableTransaction> inTxs(txs.begin(), txs.begin() + txs.size() - 1);

    auto bIndex = GenerateBlock(inTxs);
    BOOST_CHECK(bIndex);

    auto block = GetCBlock(bIndex);
    pwalletMain->sparkWallet->UpdateMintStateFromBlock(block);

    auto extractAmountsFromAvailableCoins = [](std::vector<CSparkMintMeta> const &coins) -> std::vector<CAmount> {
         std::vector<CAmount> amounts;
         for (auto const &coin : coins) {
             amounts.push_back(coin.v);
         }

         return amounts;
     };

    std::vector<CSparkMintMeta> confirmedCoins = pwalletMain->sparkWallet->ListSparkMints(true, true);
    std::vector<CSparkMintMeta> allCoins = pwalletMain->sparkWallet->ListSparkMints(true, false);
    auto confirmed = extractAmountsFromAvailableCoins(confirmedCoins);
    auto all = extractAmountsFromAvailableCoins(allCoins);

    BOOST_CHECK(std::is_permutation(confirmed.begin(), confirmed.end(), confirmedAmounts.begin()));
    BOOST_CHECK(std::is_permutation(all.begin(), all.end(), allAmounts.begin()));

    // get mint
    CSparkMintMeta mint = pwalletMain->sparkWallet->getMintMeta(mints.front().k);
    BOOST_CHECK(mint.v == mints.front().v);

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(block_mint_scan_and_queued_reorg)
{
    GenerateBlocks(1001);
    auto* wallet = pwalletMain->sparkWallet.get();
    const spark::SpendKey foreignSpendKey(params);
    const spark::FullViewKey foreignFullViewKey(foreignSpendKey);
    const spark::IncomingViewKey foreignViewKey(foreignFullViewKey);
    const std::vector<spark::MintedCoinData> outputs = {
        {wallet->getDefaultAddress(), 2 * COIN, "wallet mint"},
        {spark::Address(foreignViewKey, 0), 3 * COIN, "foreign mint"},
    };
    std::vector<std::pair<CWalletTx, CAmount>> transactions;
    BOOST_REQUIRE_EQUAL(pwalletMain->MintAndStoreSpark(outputs, transactions, false, true), "");
    BOOST_REQUIRE_EQUAL(transactions.size(), 1);
    wallet->FinishTasks();
    const CBlockIndex* index;
    bool fCheckedBalance = false;
    {
        // Connected transaction notifications still hold cs_main, so the
        // worker cannot record mints before these balance checks.
        boost::signals2::scoped_connection checkBalance(
            GetMainSignals().SyncTransaction.connect(
                [&](const CTransaction& tx, const CBlockIndex*, int posInBlock) {
                    if (posInBlock < 0 || tx.GetHash() != transactions[0].first.GetHash())
                        return;
                    AssertLockHeld(cs_main);
                    BOOST_CHECK_EQUAL(wallet->getAvailableBalance(), 2 * COIN);
                    BOOST_CHECK_EQUAL(wallet->getUnconfirmedBalance(), 0);
                    BOOST_CHECK_EQUAL(wallet->GetAvailableSparkCoins().size(), 1);
                    fCheckedBalance = true;
                }));
        index = GenerateBlock({CMutableTransaction(*transactions[0].first.tx)});
        BOOST_REQUIRE(index);
    }
    BOOST_CHECK(fCheckedBalance);
    const CBlock block = GetCBlock(index);
    wallet->FinishTasks();

    CWalletDB walletdb(pwalletMain->GetDatabase());
    const auto initial = wallet->getMintMap();
    BOOST_REQUIRE_EQUAL(initial.size(), 1);
    const auto lTagHash = initial.begin()->first;
    const auto expected = initial.begin()->second;

    // Rediscover the owned output through the block worker, without cached metadata.
    wallet->eraseMint(lTagHash, walletdb);
    int notifications = 0;
    CAmount notifiedBalance = 0;
    boost::signals2::scoped_connection connection(
        pwalletMain->NotifyTransactionChanged.connect(
            [&](CWallet*, const uint256& txid, ChangeType status) {
                if (txid == expected.txid && status == CT_UPDATED) {
                    ++notifications;
                    notifiedBalance = wallet->getAvailableBalance();
                }
            }));
    wallet->UpdateMintStateFromBlock(block);
    wallet->FinishTasks();
    connection.disconnect();
    BOOST_CHECK_EQUAL(notifications, 1);
    BOOST_CHECK_EQUAL(notifiedBalance, 2 * COIN);
    const auto scanned = wallet->getMintMap();
    BOOST_REQUIRE_EQUAL(scanned.size(), 1);
    BOOST_REQUIRE(scanned.count(lTagHash));
    const auto& actual = scanned.at(lTagHash);
    BOOST_CHECK_EQUAL(actual.nHeight, index->nHeight);
    BOOST_CHECK_EQUAL(actual.nId, expected.nId);
    BOOST_CHECK_EQUAL(actual.v, 2 * COIN);
    BOOST_CHECK_EQUAL(actual.memo, "wallet mint");
    BOOST_CHECK(actual.txid == expected.txid);
    BOOST_CHECK(actual.coin == expected.coin);
    BOOST_CHECK(actual.serial_context == expected.serial_context);
    BOOST_CHECK(!actual.isUsed);
    BOOST_CHECK(wallet->validateLookupIndexes());
    CSparkMintMeta persisted;
    BOOST_REQUIRE(walletdb.ReadSparkMint(lTagHash, persisted));
    BOOST_CHECK_EQUAL(persisted.nHeight, actual.nHeight);
    BOOST_CHECK_EQUAL(persisted.v, actual.v);
    BOOST_CHECK(persisted.coin == actual.coin);

    // The worker may identify coins now, but cannot record them until cs_main is released.
    // Disconnect first: a queued scan must not resurrect the removed wallet mint.
    {
        LOCK(cs_main);
        wallet->UpdateMintStateFromBlock(block);
        BOOST_REQUIRE(DisconnectBlocks(1));
        // Discard the resurrected mempool mint as well, leaving only the stale block job.
        mempool.clear();
        txpools.getStemTxPool().clear();
        wallet->eraseMint(lTagHash, walletdb);
    }
    wallet->FinishTasks();
    BOOST_CHECK(wallet->getMintMap().empty());
    BOOST_CHECK(!walletdb.ReadSparkMint(lTagHash, persisted));
    BOOST_CHECK(wallet->validateLookupIndexes());

    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, ::Params(), std::make_shared<CBlock>(block)));
    wallet->FinishTasks();
    BOOST_CHECK_EQUAL(wallet->getMintMap().size(), 1);
    BOOST_REQUIRE(walletdb.ReadSparkMint(lTagHash, persisted));
    BOOST_CHECK_EQUAL(persisted.nHeight, index->nHeight);
    spark::CSparkState::GetState()->Reset();
}


BOOST_AUTO_TEST_CASE(block_mint_scan_preserves_spends)
{
    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({5 * COIN, COIN}, mintTransactions);
    txpools.clear();
    const auto* index = GenerateBlock(mintTransactions);
    BOOST_REQUIRE(index);
    const CBlock block = GetCBlock(index);
    GenerateBlocks(10);

    auto* wallet = pwalletMain->sparkWallet.get();
    wallet->FinishTasks();
    const CTransaction spend = GenerateSparkSpend({4 * COIN}, {}, nullptr);
    const auto lTags = spark::GetSparkUsedTags(spend);
    BOOST_REQUIRE_EQUAL(lTags.size(), 1);
    const uint256 lTagHash = primitives::GetLTagHash(lTags[0]);
    CWalletDB walletdb(pwalletMain->GetDatabase());

    for (auto* pool : {&mempool, &txpools.getStemTxPool()}) {
        txpools.clear();
        {
            LOCK(cs_main);
            CValidationState state;
            BOOST_REQUIRE(AcceptToMemoryPool(*pool, state, MakeTransactionRef(spend), false, nullptr));
        }
        wallet->FinishTasks();

        // Rediscover the mint after its spend notification has already been processed.
        wallet->eraseMint(lTagHash, walletdb);
        walletdb.EraseSparkSpendEntry(lTags[0]);
        wallet->UpdateMintStateFromBlock(block);
        wallet->FinishTasks();

        BOOST_CHECK(wallet->getMintMeta(lTagHash).isUsed);
        CSparkMintMeta persisted;
        BOOST_REQUIRE(walletdb.ReadSparkMint(lTagHash, persisted));
        BOOST_CHECK(persisted.isUsed);
        CSparkSpendEntry entry;
        BOOST_REQUIRE(walletdb.ReadSparkSpendEntry(lTags[0], entry));
        BOOST_CHECK(entry.hashTx == spend.GetHash());
        BOOST_CHECK_EQUAL(entry.amount, persisted.v);
    }
    txpools.clear();

    // A rescan must also keep confirmed spends used after they leave both pools.
    BOOST_REQUIRE(GenerateBlock({CMutableTransaction(spend)}));
    wallet->FinishTasks();
    BOOST_REQUIRE(wallet->getMintMeta(lTagHash).isUsed);
    wallet->eraseMint(lTagHash, walletdb);
    wallet->UpdateMintStateFromBlock(block);
    wallet->FinishTasks();
    BOOST_CHECK(wallet->getMintMeta(lTagHash).isUsed);
    CSparkMintMeta persisted;
    BOOST_REQUIRE(walletdb.ReadSparkMint(lTagHash, persisted));
    BOOST_CHECK(persisted.isUsed);
    CSparkSpendEntry entry;
    BOOST_REQUIRE(walletdb.ReadSparkSpendEntry(lTags[0], entry));
    BOOST_CHECK(entry.hashTx == spend.GetHash());
    spark::CSparkState::GetState()->Reset();
}

BOOST_AUTO_TEST_CASE(spend)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);
    const uint64_t v = 2 * COIN;

    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee2;
    pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee2, false, true);

    BOOST_CHECK_EQUAL("", result);

    CMutableTransaction mutableTx(*(wtxAndFee[0].first.tx));
    CMutableTransaction mutableTx2(*(wtxAndFee2[0].first.tx));
    GenerateBlock({mutableTx, mutableTx2}, &script);
    GenerateBlocks(5);
    BOOST_CHECK_EQUAL(1, wtxAndFee.size());
    wtxAndFee.clear();

    auto spTx = GenerateSparkSpend({1 * COIN}, {}, nullptr);

    BOOST_REQUIRE(spTx.IsSparkSpend());
    const auto smint = std::find_if(
        spTx.vout.begin(), spTx.vout.end(),
        [](const CTxOut& output) {
            return output.scriptPubKey.IsSparkSMint();
        });
    BOOST_REQUIRE(smint != spTx.vout.end());
    BOOST_CHECK(pwalletMain->IsMine(*smint, spTx) & ISMINE_SPENDABLE);
    BOOST_CHECK_GT(
        pwalletMain->GetCredit(*smint, spTx, ISMINE_SPENDABLE), 0);

    std::vector<spark::Coin> coins;
    std::vector<GroupElement> tags;
    ExtractSpend(spTx, coins, tags);

    BOOST_CHECK_EQUAL(1, coins.size());
    BOOST_CHECK_EQUAL(1, tags.size());

    pwalletMain->sparkWallet->FinishTasks();
    const auto savedBalance = pwalletMain->sparkWallet->getFullBalance();
    const auto savedMints = pwalletMain->sparkWallet->getMintMap();
    BOOST_REQUIRE(std::any_of(savedMints.begin(), savedMints.end(),
        [&](const auto& mint) {
            return mint.second.txid == spTx.GetHash() && mint.second.type == spark::COIN_TYPE_SPEND;
        }));
    BOOST_REQUIRE(pwalletMain->mapWallet.count(spTx.GetHash()));
    {
        LOCK(pwalletMain->cs_wallet);
        auto parent = pwalletMain->mapWallet.extract(spTx.GetHash());
        ReloadSparkWallet();
        for (const auto& mint : pwalletMain->sparkWallet->getMintMap())
            BOOST_CHECK(mint.second.txid != spTx.GetHash());
        CWalletDB walletdb(pwalletMain->GetDatabase());
        BOOST_CHECK_EQUAL(walletdb.ListSparkMints().size(), savedMints.size());
        pwalletMain->mapWallet.insert(std::move(parent));
    }

    // A legitimate SMint is recovered when its parent becomes available again.
    ReloadSparkWallet();
    BOOST_CHECK_EQUAL(pwalletMain->sparkWallet->getFullBalance(), savedBalance);
    BOOST_CHECK_EQUAL(pwalletMain->sparkWallet->getMintMap().size(), savedMints.size());
    BOOST_CHECK(pwalletMain->sparkWallet->validateLookupIndexes());

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spend_rejects_unbound_cover_set_during_h2_policy_lead)
{
    struct RestoreSparkTestState {
        ~RestoreSparkTestState()
        {
            mempool.clear();
            spark::CSparkState::GetState()->Reset();
        }
    } restoreSparkTestState;

    struct RestoreActivationHeights {
        Consensus::Params& consensus;
        int singleInput;
        int v2;

        RestoreActivationHeights()
            : consensus(const_cast<Consensus::Params&>(
                ::Params().GetConsensus()))
            , singleInput(consensus.nSparkSingleInputStartBlock)
            , v2(consensus.nSparkChaumV2StartBlock)
        {
        }

        ~RestoreActivationHeights()
        {
            consensus.nSparkSingleInputStartBlock = singleInput;
            consensus.nSparkChaumV2StartBlock = v2;
        }
    } restoreActivationHeights;

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({2 * COIN, 2 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(5);
    pwalletMain->sparkWallet->FinishTasks();

    const int nextHeight = chainActive.Height() + 1;
    const int h2Height = nextHeight + 10;
    UpdateRegtestSparkActivationHeights(&nextHeight, &h2Height);

    try {
        GenerateSparkSpend({COIN}, {}, nullptr);
        BOOST_FAIL("Expected an unbound cover-set rejection");
    } catch (const std::runtime_error& error) {
        BOOST_CHECK_EQUAL(
            error.what(),
            "Selected Spark cover set is not yet bound to a canonical state hash");
    }
}

BOOST_AUTO_TEST_CASE(disconnect_block_rolls_back_spend)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    // mint the coins to spend from, a spend needs a cover set of at least two coins
    spark::MintedCoinData data;
    data.address = pwalletMain->sparkWallet->getDefaultAddress();
    data.v = 2 * COIN;
    data.memo = "Test memo";

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    BOOST_CHECK_EQUAL("", pwalletMain->MintAndStoreSpark({data, data}, wtxAndFee, false, true));

    std::vector<CMutableTransaction> mintTxs;
    for (const auto& wtx : wtxAndFee)
        mintTxs.emplace_back(*(wtx.first.tx));

    BOOST_REQUIRE(GenerateBlock(mintTxs));
    GenerateBlocks(5);
    BOOST_REQUIRE_EQUAL(2, pwalletMain->sparkWallet->ListSparkMints().size());

    // spend a part of it, the remainder comes back as an SMint output of the spend
    auto spendTx = GenerateSparkSpend({1 * COIN}, {}, nullptr);

    std::vector<spark::Coin> coins;
    std::vector<GroupElement> lTags;
    ExtractSpend(spendTx, coins, lTags);
    BOOST_REQUIRE_EQUAL(1, coins.size());
    BOOST_REQUIRE_EQUAL(1, lTags.size());

    auto blockIdx = GenerateBlock({CMutableTransaction(spendTx)});
    BOOST_REQUIRE(blockIdx);

    uint256 spentLTagHash = primitives::GetLTagHash(lTags[0]);

    // Leave connect and mempool wallet updates queued so they can race rollback.

    // DisconnectTip resurrects the transactions of the disconnected block into the
    // pools and keeps the wallet state of everything that makes it back. Make the
    // pools reject the spend the way a competing spend of the same coin on the new
    // chain would, so that the transaction is really gone and the wallet has to roll
    // back.
    {
        LOCK(mempool.cs);
        mempool.sparkState.AddSpendToMempool(lTags[0], spendTx.GetHash());
    }
    {
        CTxMemPool &stemPool = txpools.getStemTxPool();
        LOCK(stemPool.cs);
        stemPool.sparkState.AddSpendToMempool(lTags[0], spendTx.GetHash());
    }

    BOOST_CHECK(DisconnectBlocks(1));
    BOOST_CHECK_EQUAL(chainActive.Tip()->nHeight, blockIdx->nHeight - 1);

    pwalletMain->sparkWallet->FinishTasks();

    // the mint created by the spend is gone and the coin it spent is spendable again
    CSparkMintMeta staleMeta;
    BOOST_CHECK(!pwalletMain->sparkWallet->getMintMeta(coins[0], staleMeta));

    CSparkMintMeta spentMeta = pwalletMain->sparkWallet->getMintMeta(spentLTagHash);
    BOOST_CHECK_EQUAL(data.v, spentMeta.v);
    BOOST_CHECK(!spentMeta.isUsed);

    BOOST_CHECK_EQUAL(2, pwalletMain->sparkWallet->ListSparkMints().size());
    BOOST_CHECK_EQUAL(0, pwalletMain->sparkWallet->ListSparkSpends().size());

    mempool.clear();
    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(mintspark_and_mint_all)
{
    auto countMintsInBalance = [&](
        std::vector<std::pair<CWalletTx, CAmount>> const& wtxs,
        bool includeFee = false) -> CAmount {

        CAmount sum = 0;
        for (auto const &w : wtxs) {
            for (auto const &out : w.first.tx->vout) {
                if (out.scriptPubKey.IsSparkMint()) {
                    sum += out.nValue;
                }
             }

            if (includeFee) {
                sum += w.second;
            }
        }
        return sum;
    };

    auto getAvailableCoinsForMintBalance = [&]() -> CAmount {
        std::vector<std::pair<CAmount, std::vector<COutput>>> valueAndUTXO;
        pwalletMain->AvailableCoinsForLMint(valueAndUTXO, nullptr);
        CAmount s = 0;

        for (auto const &v : valueAndUTXO) {
            s += v.first;
        }

        return s;
    };

    CScript externalScript;
    {
        uint160 seed;
        GetRandBytes(seed.begin(), seed.size());

        externalScript = GetScriptForDestination(CKeyID(seed));
    }

    auto generateBlocksPerScripts = [&](size_t blocks, size_t blocksPerScript) -> std::vector<CScript> {
        std::vector<CScript> scripts;
        while (blocks != 0) {
            CPubKey key;
            {
                LOCK(pwalletMain->cs_wallet);
                key = pwalletMain->GenerateNewKey();
            }
            scripts.push_back(GetScriptForDestination(key.GetID()));
            auto blockCount = std::min(blocksPerScript, blocks);
            GenerateBlocks(blockCount, &scripts.back());
            blocks -= blockCount;
        }

        return scripts;
    };

    auto scripts = generateBlocksPerScripts(200, 10);
    GenerateBlocks(100, &externalScript);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    const uint64_t v = 10 * COIN;

    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";
    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    auto result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_EQUAL(1, wtxAndFee.size());
    BOOST_CHECK_EQUAL(10 * COIN, countMintsInBalance(wtxAndFee));
    wtxAndFee.clear();
    mintedCoins.clear();

    data.v = 600 * COIN;;
    mintedCoins.clear();
    mintedCoins.push_back(data);

    result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_GT(wtxAndFee.size(), 1);
    BOOST_CHECK_EQUAL(600 * COIN, countMintsInBalance(wtxAndFee));

    wtxAndFee.clear();
    mintedCoins.clear();

    auto balance = getAvailableCoinsForMintBalance();
    BOOST_CHECK_GT(balance, 0);

    result = pwalletMain->MintAndStoreSpark({}, wtxAndFee, false, true, true);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_GT(balance, countMintsInBalance(wtxAndFee));
    BOOST_CHECK_EQUAL(balance, countMintsInBalance(wtxAndFee, true));
    BOOST_CHECK_EQUAL(0, getAvailableCoinsForMintBalance());

    scripts = generateBlocksPerScripts(500, 200);
    GenerateBlocks(100, &externalScript);

    wtxAndFee.clear();
    mintedCoins.clear();
    balance = getAvailableCoinsForMintBalance();
    BOOST_CHECK_GT(balance, 0);

    result = pwalletMain->MintAndStoreSpark({ }, wtxAndFee, false, true, true);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_GT(balance, countMintsInBalance(wtxAndFee));
    BOOST_CHECK_EQUAL(balance, countMintsInBalance(wtxAndFee, true));
    BOOST_CHECK_EQUAL(0, pwalletMain->GetBalance());

    // Scripts of all changes should unique
    std::set<CScript> changeScripts;
    for (auto const &wtx : wtxAndFee) {
        for (auto const &out : wtx.first.tx->vout) {
            if (!out.scriptPubKey.IsSparkMint()) {
                BOOST_CHECK(!changeScripts.count(out.scriptPubKey));
                changeScripts.insert(out.scriptPubKey);
            }
        }
    }

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
