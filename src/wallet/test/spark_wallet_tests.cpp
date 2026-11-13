#include <../../test/fixtures.h>
#include "../../chainparams.h"
#include "../../policy/policy.h"
#include "../../spark/state.h"
#include "../coincontrol.h"
#include "../rpcsparkmultisig.h"
#include "../wallet.h"
#include "../walletdb.h"
#include "../../base58.h"
#include "../../rpc/server.h"
#include "../../utilstrencodings.h"
#include "../../spark/sparkwallet.h"
#include "../../streams.h"
#include "../../validation.h"
#include "../../validationinterface.h"

#include <algorithm>
#include <atomic>
#include <boost/test/unit_test.hpp>
#include <limits>

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
    pwalletMain->sparkWallet = std::make_unique<CSparkWallet>(pwalletMain->strWalletFile);
}

class ReadableWalletDB : public CWalletDB {
public:
    using CWalletDB::CWalletDB;
    using CWalletDB::Read;
};

extern std::atomic<bool> fRequestShutdown;

BOOST_FIXTURE_TEST_SUITE(spark_wallet_tests, SparkTestingSetup)

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
        CWalletDB walletdb(pwalletMain->strWalletFile);
        pwalletMain->sparkWallet->UpdateMintState(
            {coin}, mixedTransaction.GetHash(), walletdb);
        BOOST_REQUIRE_EQUAL(walletdb.ListSparkMints().size(), 1U);
    }
    BOOST_CHECK_EQUAL(pwalletMain->sparkWallet->getUnconfirmedBalance(), 100 * COIN);

    // Missing parents must not make saved metadata authoritative. Keep the
    // database record for recovery, but exclude it from balances and lookups.
    for (int height : {-1, 1}) {
        CWalletDB walletdb(pwalletMain->strWalletFile);
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
    CWalletDB walletdb(pwalletMain->strWalletFile);
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

    CWalletDB walletdb(pwalletMain->strWalletFile);
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
    CWalletDB walletdb(pwalletMain->strWalletFile);

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
        CWalletDB walletdb(pwalletMain->strWalletFile);
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

// Run a Spark multisig RPC and return the error message it fails with, or nothing
static std::string MultisigError(UniValue (*rpc)(const JSONRPCRequest&), const UniValue& param, UniValue* result = nullptr)
{
    JSONRPCRequest request;
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(param);
    try {
        const UniValue value = rpc(request);
        if (result) {
            *result = value;
        }
    } catch (const UniValue& error) {
        return find_value(error, "message").get_str();
    }
    return "";
}

static std::string SealMultisigSpend(const spark::MultisigKey& key, const CSparkMultisigSpend& spend)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << spend;
    return HexStr(key.seal(spark::Params::get_default(), stream));
}

static CSparkMultisigSpend OpenMultisigSpend(const spark::MultisigKey& key, const std::string& hex)
{
    CSparkMultisigSpend spend;
    key.open(spark::Params::get_default(), ParseHex(hex)) >> spend;
    return spend;
}

// A cosigner can produce any validly sealed spend. What a signer accepts must not
// depend on the cosigner being honest.
BOOST_AUTO_TEST_CASE(multisig_signer_checks_the_spend)
{
    const spark::Params* params = spark::Params::get_default();

    // Make this wallet one of two participants who both have to sign
    const CPubKey pubkey = GenerateAddress();
    CKey privkey;
    BOOST_REQUIRE(pwalletMain->GetKey(pubkey.GetID(), privkey));
    Scalar own, other;
    own.deserialize(privkey.begin());
    other.randomize();
    const std::vector<GroupElement> participants = {params->get_G()*own, params->get_G()*other};
    const spark::MultisigKeygen ownKeygen(params, 2, participants, own);
    const spark::MultisigKeygen otherKeygen(params, 2, participants, other);
    const std::vector<spark::MultisigKeygenMessage> round1 = {ownKeygen.round1(), otherKeygen.round1()};
    const std::vector<spark::MultisigKeygenMessage> round2 = {ownKeygen.round2(round1), otherKeygen.round2(round1)};
    const spark::MultisigKey key = ownKeygen.finalize(round2);
    const spark::MultisigKey otherKey = otherKeygen.finalize(round2);
    {
        CWalletDB walletdb(pwalletMain->strWalletFile);
        BOOST_REQUIRE(walletdb.WriteSparkMultisigKey(key));
        BOOST_REQUIRE(walletdb.writeFullViewKey(key.get_full_view_key(params)));
    }
    ReloadSparkWallet();
    BOOST_REQUIRE(pwalletMain->sparkWallet->getMultisigKey());

    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);
    std::vector<CMutableTransaction> mintTxs;
    GenerateMints({10 * COIN, 10 * COIN}, mintTxs);
    GenerateBlock(mintTxs, &script);
    GenerateBlocks(5);
    pwalletMain->sparkWallet->WaitForPendingTasks();

    // The wallet no longer spends on its own
    const CRecipient transparent{GetScriptForDestination(GenerateAddress().GetID()), COIN, false, {}, {}};
    CAmount fee = 0;
    BOOST_CHECK_THROW(pwalletMain->CreateSparkSpendTransaction({transparent}, {}, fee, nullptr), std::runtime_error);
    BOOST_CHECK_THROW(pwalletMain->sparkWallet->SignMessage(pwalletMain->sparkWallet->getDefaultAddress(), "message"), std::runtime_error);

    // A spend to a transparent address and to someone else's Spark address
    const spark::Address foreign(spark::IncomingViewKey(spark::FullViewKey(spark::SpendKey(params))), 1);
    UniValue amount(UniValue::VOBJ);
    amount.push_back(Pair("amount", 1));
    amount.push_back(Pair("subtractFee", false));
    UniValue recipients(UniValue::VOBJ);
    recipients.push_back(Pair(CBitcoinAddress(GenerateAddress().GetID()).ToString(), amount));
    recipients.push_back(Pair(foreign.encode(spark::GetNetworkType()), amount));
    UniValue created;
    BOOST_REQUIRE_EQUAL(MultisigError(createsparkmultisigspend, recipients, &created), "");
    const std::string hex = created["hex"].get_str();
    BOOST_CHECK_EQUAL(MultisigError(decodesparkmultisigspend, hex), "");

    const CSparkMultisigSpend spend = OpenMultisigSpend(key, hex);
    BOOST_REQUIRE_EQUAL(spend.outputs.size(), 2); // the payment and the change
    BOOST_REQUIRE(!spend.tx.vout[0].scriptPubKey.IsSparkSMint());

    const auto rejects = [&](const CSparkMultisigSpend& bad, const std::string& reason) {
        for (const auto rpc : {decodesparkmultisigspend, signsparkmultisigspend}) {
            const std::string error = MultisigError(rpc, SealMultisigSpend(key, bad));
            BOOST_CHECK_MESSAGE(error.find(reason) != std::string::npos, "expected '" + reason + "', got '" + error + "'");
        }
    };

    // What a spend says about an output has to be the output
    CSparkMultisigSpend bad = spend;
    bad.outputs[0].amount += 1;
    rejects(bad, "does not match its description");
    bad = spend;
    bad.outputs[0].memo = "other";
    rejects(bad, "does not match its description");
    bad = spend;
    std::swap(bad.outputs[0].address, bad.outputs[1].address);
    rejects(bad, "does not match its description");
    bad = spend;
    bad.outputs.pop_back();
    rejects(bad, "not all described");

    // The transparent part is tied to the signature through the cover set data
    bad = spend;
    bad.tx.vout[0].nValue += 1;
    rejects(bad, "cover set data of another transaction");
    bad = spend;
    bad.coverSets.begin()->second.second.back() ^= 1;
    rejects(bad, "cover set data of another transaction");
    bad = spend;
    bad.coverSets.clear();
    rejects(bad, "missing cover set data");

    // A fee above the wallet's limit is not signed
    const CAmount savedMaxTxFee = maxTxFee;
    maxTxFee = 1;
    BOOST_CHECK(MultisigError(signsparkmultisigspend, hex).find("-maxtxfee") != std::string::npos);
    maxTxFee = savedMaxTxFee;

    // The wallet commits to the spend, and so does the other signer
    const auto commit = [&]() {
        UniValue committed;
        BOOST_REQUIRE_EQUAL(MultisigError(signsparkmultisigspend, hex, &committed), "");
        BOOST_REQUIRE(!committed["complete"].get_bool());
        CSparkMultisigSpend session = OpenMultisigSpend(key, committed["hex"].get_str());
        BOOST_REQUIRE_EQUAL(session.commitments.size(), 1);
        BOOST_REQUIRE(session.shares.empty());
        spark::MultisigNonce nonce;
        session.commitments.emplace_back(spark::MultisigSession::commit(params, otherKey.index, session.commitments[0].D.size(), other, nonce));
        return session;
    };
    const CSparkMultisigSpend session = commit();

    // From here the cosigner cannot change anything the proof's challenge depends on.
    // The block a cover set is taken at is such a thing, and the one that neither the
    // binding hash nor the wallet's other checks cover.
    CSparkMultisigSpend steered = session;
    spark::SpendTransaction payload = spark::ParseSparkSpend(CTransaction(steered.tx));
    std::map<uint64_t, uint256> blockHashes = payload.getBlockHashes();
    blockHashes.begin()->second = uint256S("01");
    payload.setBlockHashes(blockHashes);
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << payload;
    steered.tx.vExtraPayload.assign(serialized.begin(), serialized.end());
    BOOST_CHECK_EQUAL(MultisigError(decodesparkmultisigspend, SealMultisigSpend(key, steered)), "");
    BOOST_CHECK(MultisigError(signsparkmultisigspend, SealMultisigSpend(key, steered)).find("changed after") != std::string::npos);

    // The attempt used up the nonce
    BOOST_CHECK(MultisigError(signsparkmultisigspend, SealMultisigSpend(key, session)).find("no longer holds the nonce") != std::string::npos);

    // Left alone, the spend gets the wallet's signature share, once
    const CSparkMultisigSpend again = commit();
    UniValue signedSpend;
    BOOST_REQUIRE_EQUAL(MultisigError(signsparkmultisigspend, SealMultisigSpend(key, again), &signedSpend), "");
    BOOST_CHECK(!signedSpend["complete"].get_bool());
    const CSparkMultisigSpend result = OpenMultisigSpend(key, signedSpend["hex"].get_str());
    BOOST_REQUIRE_EQUAL(result.shares.size(), 1);
    BOOST_CHECK_EQUAL(result.shares[0].index, key.index);
    BOOST_CHECK(MultisigError(signsparkmultisigspend, SealMultisigSpend(key, again)).find("no longer holds the nonce") != std::string::npos);

    // A share that is not the other signer's does not complete the spend
    CSparkMultisigSpend forged = result;
    forged.shares.emplace_back(result.shares[0]);
    forged.shares.back().index = otherKey.index;
    BOOST_CHECK(MultisigError(combinesparkmultisigspend, UniValue(UniValue::VARR)).find("at least one") != std::string::npos);
    UniValue list(UniValue::VARR);
    list.push_back(SealMultisigSpend(key, forged));
    BOOST_CHECK(MultisigError(combinesparkmultisigspend, list).find("Bad signature share") != std::string::npos);

    spark::CSparkState::GetState()->Reset();
}

BOOST_AUTO_TEST_CASE(multisig_setup_retires_old_receive_addresses)
{
    const spark::Params* params = spark::Params::get_default();
    const std::string oldAddress = pwalletMain->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType());
    BOOST_REQUIRE(pwalletMain->SetSparkAddressBook(oldAddress, "old address", "receive"));
    BOOST_REQUIRE(pwalletMain->AddDestData(oldAddress, "rr1", "saved receive request"));

    const spark::Address contact(spark::IncomingViewKey(spark::FullViewKey(spark::SpendKey(params))), 1);
    const std::string contactAddress = contact.encode(spark::GetNetworkType());
    BOOST_REQUIRE(pwalletMain->SetSparkAddressBook(contactAddress, "friend", "send"));

    const CPubKey ownPubKey = GenerateAddress();
    CKey ownKey;
    BOOST_REQUIRE(pwalletMain->GetKey(ownPubKey.GetID(), ownKey));
    Scalar ownSecret, otherSecret;
    ownSecret.deserialize(ownKey.begin());
    otherSecret.randomize();
    const std::vector<GroupElement> participants = {
        params->get_G()*ownSecret, params->get_G()*otherSecret};
    const spark::MultisigKeygen other(params, 2, participants, otherSecret);
    const spark::MultisigKeygen local(params, 2, participants, ownSecret);

    UniValue keys(UniValue::VARR);
    for (const auto& participant : participants)
        keys.push_back(HexStr(spark::MultisigKey::serialize_participant(participant)));
    JSONRPCRequest request;
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(2);
    request.params.push_back(keys);
    BOOST_CHECK(!addsparkmultisigaddress(request)["complete"].get_bool());

    const auto encode = [](const spark::MultisigKeygenMessage& message) {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << message;
        return HexStr(stream.begin(), stream.end());
    };
    const auto first = {local.round1(), other.round1()};
    UniValue data(UniValue::VARR);
    data.push_back(encode(other.round1()));
    request.params.push_back(data);
    BOOST_CHECK(!addsparkmultisigaddress(request)["complete"].get_bool());

    data = UniValue(UniValue::VARR);
    data.push_back(encode(other.round2(first)));
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(2);
    request.params.push_back(keys);
    request.params.push_back(data);
    const UniValue completed = addsparkmultisigaddress(request);
    fRequestShutdown = false; // The unit runner continues after this RPC.
    BOOST_REQUIRE(completed["complete"].get_bool());

    ReadableWalletDB walletdb(pwalletMain->strWalletFile);
    std::string purpose, name, receiveRequest;
    BOOST_REQUIRE(walletdb.Read(std::make_pair(std::string("purpose"), oldAddress), purpose));
    BOOST_CHECK_EQUAL(purpose, "retired");
    BOOST_REQUIRE(walletdb.Read(std::make_pair(std::string("name"), oldAddress), name));
    BOOST_CHECK_EQUAL(name, "old address");
    BOOST_CHECK(!walletdb.Read(std::make_pair(std::string("destdata"), std::make_pair(oldAddress, std::string("rr1"))), receiveRequest));
    BOOST_REQUIRE(walletdb.Read(std::make_pair(std::string("purpose"), contactAddress), purpose));
    BOOST_CHECK_EQUAL(purpose, "send");

    // A payment to the old address can still arrive before the node is down. The
    // wallet does not record it: after the restart it would list a coin of other keys.
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);
    std::vector<CMutableTransaction> mintTxs;
    GenerateMints({10 * COIN}, mintTxs);
    BOOST_REQUIRE(GenerateBlock(mintTxs, &script));
    pwalletMain->sparkWallet->WaitForPendingTasks();
    ReloadSparkWallet();
    BOOST_REQUIRE(pwalletMain->sparkWallet->getMultisigKey());
    BOOST_CHECK(pwalletMain->sparkWallet->getMintMap().empty());

    spark::CSparkState::GetState()->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
