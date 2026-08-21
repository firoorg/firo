#include "../chainparams.h"
#include "../script/standard.h"
#include "../validation.h"
#include "../wallet/coincontrol.h"
#include "../wallet/wallet.h"
#include "../wallet/walletexcept.h"
#include "../net.h"
#include "../policy/policy.h"
#include "../sparkname.h"

#include "compat_layer.h"
#include "test_bitcoin.h"
#include "fixtures.h"
#include <iostream>
#include <boost/test/unit_test.hpp>
#include <univalue.h>

UniValue CallRPC(std::string args);

namespace spark {

class SparkNameTests : public SparkTestingSetup
{
public:
    Consensus::Params &mutableConsensus;

private:
    Consensus::Params oldConsensus;

public:
    SparkNameTests() :
          SparkTestingSetup(),
          mutableConsensus(const_cast<Consensus::Params &>(::Params().GetConsensus())),
          sparkState(CSparkState::GetState()),
          consensus(::Params().GetConsensus()),
          sparkNameManager(CSparkNameManager::GetInstance()) {
        oldConsensus = mutableConsensus;
        mempool.clear();
    }

    ~SparkNameTests() {
       mempool.clear();
       sparkState->Reset();
       sparkNameManager->Reset();
       mutableConsensus = oldConsensus;
    }

    bool IsSparkNamePresent(std::string const &name) {
        std::string address;
        return sparkNameManager->GetSparkAddress(name, address);
    }

    std::string GetSparkNameAdditionalData(const std::string &name) {
        BOOST_CHECK(IsSparkNamePresent(name));
        return sparkNameManager->GetSparkNameAdditionalData(name);
    }

    void Initialize(int numberOfBlocks = 2000) {
        std::vector<CMutableTransaction> mintTxs;
        GenerateBlocks(numberOfBlocks-1);
        // Each name registration must be funded by one Spark coin large enough to
        // cover the registration fee plus the transaction fee. Several tests register
        // consecutive names without mining between them, so each registration's change
        // is still unconfirmed when the next one is built. The wallet therefore needs
        // one spendable coin per registration that is large enough on its own. A
        // 4-character name costs 10 FIRO per year,
        // which the 10 FIRO coins below cannot cover once the fee is added.
        GenerateMints({50 * COIN, 60 * COIN, 50 * COIN, 50 * COIN, 50 * COIN,
                       10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN}, mintTxs);
        GenerateBlock(mintTxs);
        pwalletMain->SetBroadcastTransactions(true);
    }

    std::string GenerateSparkAddress() {
        const spark::Params *params = spark::Params::get_default();
        spark::Address address(params);

        LOCK(pwalletMain->cs_wallet);
        address = pwalletMain->sparkWallet->generateNewAddress();
        unsigned char network = spark::GetNetworkType();
        std::string sparkAddressStr = address.encode(network);

        pwalletMain->SetSparkAddressBook(sparkAddressStr, "", "receive");
        return sparkAddressStr;
    }

    CMutableTransaction CreateSparkNameTx(CSparkNameTxData &sparkNameData, bool fCommit = false, CAmount sparkNameFee = 0) {
        LOCK(cs_main);
        LOCK(pwalletMain->cs_wallet);

        CAmount txFee;
        FIRO_UNUSED size_t additionalSize = sparkNameManager->GetSparkNameTxDataSize(sparkNameData);

        if (sparkNameFee == 0) {
            BOOST_ASSERT(sparkNameData.name.length() <= CSparkNameManager::maximumSparkNameLength);
            int numberOfYears = (sparkNameData.sparkNameValidityBlocks + 24 * 24 * 365 - 1) / (24 * 24 * 365);    
            sparkNameFee = consensus.nSparkNamesFee[sparkNameData.name.length()] * COIN * numberOfYears;
        }

        CWalletTx sparkNameWalletTx = pwalletMain->sparkWallet->CreateSparkNameTransaction(sparkNameData, sparkNameFee, txFee, nullptr);
        if (fCommit) {
            CReserveKey reserveKey(pwalletMain);
            lastState = CValidationState();
            pwalletMain->CommitTransaction(sparkNameWalletTx, reserveKey, g_connman.get(), lastState);
        }
        return CMutableTransaction(*sparkNameWalletTx.tx);
    }

    CMutableTransaction CreateSparkNameTx(const std::string &name, const std::string &address, uint32_t sparkNameValidityHeight, const std::string &additionalInfo, bool fCommit = false, CAmount sparkNameFee = 0) {
        CSparkNameTxData sparkNameData;
        sparkNameData.name = name;
        sparkNameData.nVersion = 1;
        sparkNameData.sparkAddress = address;
        sparkNameData.sparkNameValidityBlocks = sparkNameValidityHeight;
        sparkNameData.additionalInfo = additionalInfo;

        return CreateSparkNameTx(sparkNameData, fCommit, sparkNameFee);
    }

    CBlockIndex *DisconnectAndInvalidate() {
        LOCK(cs_main);
        CBlockIndex *pindex = chainActive.Tip();
        DisconnectBlocks(1);
        CValidationState state;
        const CChainParams &chainparams = ::Params();
        InvalidateBlock(state, chainparams, pindex);
        return pindex;
    }

    void ModifySparkNameTx(CMutableTransaction &tx, std::function<void(CSparkNameTxData &)> modify, bool fRecalcOwnershipProof = true) {
        const spark::Params *params = spark::Params::get_default();
        spark::SpendTransaction sparkTx(params);

        CSparkNameTxData sparkNameData;
        size_t sparkNameDataPos;
        BOOST_CHECK(sparkNameManager->ParseSparkNameTxData(tx, sparkTx, sparkNameData, sparkNameDataPos));

        modify(sparkNameData);

        if (fRecalcOwnershipProof) {
            const bool useChaumV2 =
                tx.nType == TRANSACTION_SPARK_V2;
            for (uint32_t n=0; ; ++n) {
                sparkNameData.addressOwnershipProof.clear();
                if (!useChaumV2) {
                    sparkNameData.hashFailsafe = n;
                }
        
                CMutableTransaction txCopy(tx);
                CDataStream serializedSparkNameData(SER_NETWORK, PROTOCOL_VERSION);
                serializedSparkNameData << sparkNameData;
                txCopy.vExtraPayload.erase(txCopy.vExtraPayload.begin() + sparkNameDataPos, txCopy.vExtraPayload.end());
                txCopy.vExtraPayload.insert(txCopy.vExtraPayload.end(), serializedSparkNameData.begin(), serializedSparkNameData.end());
        
                CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
                ss << txCopy;
        
                spark::Scalar m;
                try {
                    m = CSparkNameManager::GetSparkNameOwnershipMessage(
                        ss.GetHash(), useChaumV2);
                }
                catch (const std::bad_alloc &) {
                    throw;
                }
                catch (const std::exception &) {
                    if (useChaumV2) {
                        throw;
                    }
                    continue;   // increase hashFailSafe and try again
                }
        
                spark::Address sparkAddress(spark::Params::get_default());
                spark::OwnershipProof ownershipProof;
        
                spark::SpendKey spendKey(spark::Params::get_default());
                try {
                    spendKey = std::move(pwalletMain->sparkWallet->generateSpendKey(spark::Params::get_default()));
                } catch (const WalletLocked&) {
                    BOOST_FAIL("Spark wallet is locked; unlock wallet to run this test");
                }
                spark::IncomingViewKey incomingViewKey(spendKey);
                sparkAddress.decode(sparkNameData.sparkAddress);
                sparkAddress.prove_own(m, spendKey, incomingViewKey, ownershipProof);
        
                CDataStream ownershipProofStream(SER_NETWORK, PROTOCOL_VERSION);
                ownershipProofStream << ownershipProof;
        
                sparkNameData.addressOwnershipProof.assign(ownershipProofStream.begin(), ownershipProofStream.end());
        
                break;
            }
        }

        CDataStream serializedSpark(SER_NETWORK, PROTOCOL_VERSION);
        serializedSpark << sparkNameData;

        tx.vExtraPayload.erase(tx.vExtraPayload.begin() + sparkNameDataPos, tx.vExtraPayload.end());
        tx.vExtraPayload.insert(tx.vExtraPayload.end(), serializedSpark.begin(), serializedSpark.end());
    }

    CSparkState *sparkState;
    Consensus::Params const &consensus;

    CSparkNameManager *sparkNameManager;
    CValidationState lastState;
};

} // namespace spark

BOOST_FIXTURE_TEST_SUITE(sparknames, spark::SparkNameTests)

BOOST_AUTO_TEST_CASE(chaum_v2_name_extension_is_canonical_and_bound)
{
    Initialize();
    const int v2Height = chainActive.Height() + 1;
    mutableConsensus.nSparkSingleInputStartBlock = v2Height;
    mutableConsensus.nSparkChaumV2StartBlock = v2Height;
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;

    CSparkNameTxData data;
    data.nVersion = CSparkNameTxData::CURRENT_VERSION;
    data.name = "v2-bound-name";
    data.sparkAddress = GenerateSparkAddress();
    data.sparkNameValidityBlocks = 365 * 24 * 24;
    data.additionalInfo = "bound";
    data.hashFailsafe = 7;

    uint256 outOfRangeDigest;
    outOfRangeDigest.SetHex(std::string(64, 'f'));
    BOOST_CHECK_THROW(
        CSparkNameManager::GetSparkNameOwnershipMessage(
            outOfRangeDigest, false),
        std::runtime_error);
    BOOST_CHECK_NO_THROW(
        CSparkNameManager::GetSparkNameOwnershipMessage(
            outOfRangeDigest, true));

    CMutableTransaction nameTx = CreateSparkNameTx(data, false);
    BOOST_REQUIRE(CTransaction(nameTx).IsSparkSpendV2());

    BOOST_REQUIRE_NO_THROW(spark::ParseSparkSpend(CTransaction(nameTx)));
    CValidationState nameState;
    BOOST_REQUIRE_MESSAGE(sparkNameManager->CheckSparkNameTx(
        CTransaction(nameTx), v2Height, nameState), FormatStateMessage(nameState));
    CValidationState spendState;
    BOOST_REQUIRE_MESSAGE(spark::CheckSparkTransaction(
        CTransaction(nameTx), spendState, nameTx.GetHash(), false, v2Height,
        false, true, nullptr), spendState.GetRejectReason());

    CValidationState validState;
    BOOST_REQUIRE_MESSAGE(CheckTransaction(
        CTransaction(nameTx), validState, false, nameTx.GetHash(), false,
        v2Height, false, true, nullptr), validState.GetRejectReason());

    spark::SpendTransaction spend(spark::Params::get_default());
    CSparkNameTxData parsed;
    std::size_t extensionPosition = 0;
    BOOST_REQUIRE(sparkNameManager->ParseSparkNameTxData(
        nameTx, spend, parsed, extensionPosition));
    BOOST_CHECK(!spend.getExtensionCommitment().IsNull());
    BOOST_CHECK_EQUAL(
        spend.getExtensionCommitment().ToString(),
        CSparkNameManager::GetSparkNameCommitment(parsed).ToString());

    // Removing a name suffix must not turn a pending registration into an
    // ordinary spend that consumes the same tag and burns the name fee.
    CMutableTransaction stripped(nameTx);
    stripped.vExtraPayload.resize(extensionPosition);
    CValidationState strippedState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(stripped), strippedState, false, stripped.GetHash(),
        false, v2Height, false, true, nullptr));

    // Semantic extension mutations are bound by the V2 proof.
    CMutableTransaction changed(nameTx);
    ModifySparkNameTx(changed, [](CSparkNameTxData& changedData) {
        changedData.additionalInfo = "not-bound";
    }, false);
    CValidationState changedState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(changed), changedState, false, changed.GetHash(),
        false, v2Height, false, true, nullptr));

    CMutableTransaction tailedExtension(nameTx);
    tailedExtension.vExtraPayload.push_back(0);
    CValidationState tailedExtensionState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(tailedExtension), tailedExtensionState, false,
        tailedExtension.GetHash(), false, v2Height, false, true, nullptr));

    // Ownership-proof byte vectors must contain exactly one proof.
    CMutableTransaction tailedProof(nameTx);
    ModifySparkNameTx(tailedProof, [](CSparkNameTxData& changedData) {
        changedData.addressOwnershipProof.push_back(0);
    }, false);
    CValidationState tailedProofState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(tailedProof), tailedProofState, false,
        tailedProof.GetHash(), false, v2Height, false, true, nullptr));

    // A noncanonical GroupElement flag can deserialize to a usable point for
    // some encodings. Reject the raw encoding before proof verification so it
    // cannot malleate the txid even when it represents the same proof.
    CMutableTransaction noncanonicalProof(nameTx);
    ModifySparkNameTx(noncanonicalProof, [](CSparkNameTxData& changedData) {
        BOOST_REQUIRE_GT(changedData.addressOwnershipProof.size(), 32U);
        changedData.addressOwnershipProof[32] += 2;
    }, false);
    CValidationState noncanonicalProofState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(noncanonicalProof), noncanonicalProofState, false,
        noncanonicalProof.GetHash(), false, v2Height, false, true, nullptr));

    const int beforeNameBlock = chainActive.Height();
    BOOST_REQUIRE(GenerateBlock({nameTx}));
    BOOST_CHECK_EQUAL(chainActive.Height(), beforeNameBlock + 1);
}

BOOST_AUTO_TEST_CASE(chaum_v2_name_fee_covers_final_payload)
{
    Initialize(510);
    const int nextHeight = chainActive.Height() + 1;
    mutableConsensus.nSparkSingleInputStartBlock = nextHeight;
    mutableConsensus.nSparkChaumV2StartBlock = nextHeight;
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;

    CSparkNameTxData nameData;
    nameData.name = "v2-final-fee";
    nameData.sparkAddress = GenerateSparkAddress();
    nameData.sparkNameValidityBlocks = 365 * 24 * 24;

    CCoinControl feeControl;
    feeControl.fOverrideFeeRate = true;
    feeControl.nFeeRate = CFeeRate(1000000);

    const CAmount nameFee =
        mutableConsensus.nSparkNamesFee[nameData.name.length()] * COIN;
    CAmount transactionFee = 0;
    const CWalletTx transaction =
        pwalletMain->CreateSparkNameTransaction(
            nameData,
            nameFee,
            transactionFee,
            &feeControl,
            nextHeight);
    BOOST_REQUIRE(transaction.tx);
    BOOST_REQUIRE(transaction.tx->IsSparkSpendV2());
    BOOST_CHECK_GE(
        transactionFee,
        CWallet::GetMinimumFee(
            GetVirtualTransactionSize(*transaction.tx),
            &feeControl,
            mempool));
}

BOOST_AUTO_TEST_CASE(spark_name_construction_rejects_stale_next_block_height)
{
    Initialize();
    mutableConsensus.nSparkNamesStartBlock = 1;

    CSparkNameTxData nameData;
    nameData.name = "height-race";
    nameData.sparkAddress = GenerateSparkAddress();
    nameData.sparkNameValidityBlocks = 365 * 24 * 24;

    const int nextHeight = chainActive.Height() + 1;
    nameData.nVersion = nextHeight >= mutableConsensus.nSparkNamesV2StartBlock
        ? CSparkNameTxData::CURRENT_VERSION
        : 1;

    const CAmount nameFee =
        mutableConsensus.nSparkNamesFee[nameData.name.length()] * COIN;
    CAmount transactionFee = 0;
    BOOST_CHECK_THROW(
        pwalletMain->CreateSparkNameTransaction(
            nameData,
            nameFee,
            transactionFee,
            nullptr,
            nextHeight + 1),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(chaum_v1_name_fee_requires_canonical_metadata_after_v2_activation)
{
    Initialize();
    const int singleInputHeight = chainActive.Height() + 1;
    const int v2Height = singleInputHeight + 1;
    mutableConsensus.nSparkSingleInputStartBlock = singleInputHeight;
    mutableConsensus.nSparkChaumV2StartBlock = v2Height;
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;

    CSparkNameTxData data;
    data.nVersion = CSparkNameTxData::CURRENT_VERSION;
    data.name = "v1-canonical-name";
    data.sparkAddress = GenerateSparkAddress();
    data.sparkNameValidityBlocks = 365 * 24 * 24;

    CMutableTransaction nameTx = CreateSparkNameTx(data, false);
    BOOST_REQUIRE(CTransaction(nameTx).IsSparkSpendV1());

    CValidationState validState;
    BOOST_REQUIRE(CheckTransaction(
        CTransaction(nameTx), validState, false, nameTx.GetHash(), false,
        v2Height, false, true, nullptr));

    spark::SpendTransaction spend(spark::Params::get_default());
    CSparkNameTxData parsed;
    std::size_t extensionPosition = 0;
    BOOST_REQUIRE(sparkNameManager->ParseSparkNameTxData(
        nameTx, spend, parsed, extensionPosition, true));

    CMutableTransaction stripped(nameTx);
    stripped.vExtraPayload.resize(extensionPosition);
    CValidationState historicalStrippedState;
    BOOST_REQUIRE(CheckTransaction(
        CTransaction(stripped), historicalStrippedState, false,
        stripped.GetHash(), false, singleInputHeight, false, true, nullptr));
    CValidationState strippedState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(stripped), strippedState, false, stripped.GetHash(),
        false, v2Height, false, true, nullptr));

    CMutableTransaction tailed(nameTx);
    tailed.vExtraPayload.push_back(0);
    CValidationState historicalTailedState;
    BOOST_REQUIRE(CheckTransaction(
        CTransaction(tailed), historicalTailedState, false,
        tailed.GetHash(), false, singleInputHeight, false, true, nullptr));
    CValidationState tailedState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(tailed), tailedState, false, tailed.GetHash(), false,
        v2Height, false, true, nullptr));

    CMutableTransaction tailedProof(nameTx);
    ModifySparkNameTx(tailedProof, [](CSparkNameTxData& changedData) {
        changedData.addressOwnershipProof.push_back(0);
    }, false);
    CValidationState tailedProofState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(tailedProof), tailedProofState, false,
        tailedProof.GetHash(), false, v2Height, false, true, nullptr));
}

BOOST_AUTO_TEST_CASE(chaum_v2_transfer_binds_canonical_extension)
{
    constexpr uint32_t blocksPerYear = 365 * 24 * 24;
    Initialize();
    const int v2Height = chainActive.Height() + 1;
    mutableConsensus.nSparkSingleInputStartBlock = v2Height;
    mutableConsensus.nSparkChaumV2StartBlock = v2Height;
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;

    const std::string addressA = GenerateSparkAddress();
    CSparkNameTxData registration;
    registration.nVersion = CSparkNameTxData::CURRENT_VERSION;
    registration.name = "v2-transfer-name";
    registration.sparkAddress = addressA;
    registration.sparkNameValidityBlocks = blocksPerYear;
    CMutableTransaction registrationTx =
        CreateSparkNameTx(registration, false);
    BOOST_REQUIRE(CTransaction(registrationTx).IsSparkSpendV2());
    CBlockIndex* registrationIndex = GenerateBlock({registrationTx});
    BOOST_REQUIRE(registrationIndex);
    const auto registrationRecord = registrationIndex->addedSparkNames.find(
        CSparkNameManager::ToUpper(registration.name));
    BOOST_REQUIRE(
        registrationRecord != registrationIndex->addedSparkNames.end());
    const uint64_t registrationExpiration =
        registrationRecord->second.sparkNameValidityHeight;

    CSparkNameTxData transfer;
    transfer.nVersion = CSparkNameTxData::CURRENT_VERSION;
    transfer.operationType = CSparkNameTxData::opTransfer;
    transfer.name = registration.name;
    transfer.oldSparkAddress = addressA;
    transfer.sparkAddress = GenerateSparkAddress();
    transfer.sparkNameValidityBlocks = blocksPerYear;
    CHashWriter inputsHash(SER_GETHASH, PROTOCOL_VERSION);
    inputsHash << sparkNameManager->GetSparkNameBlockHeight(transfer.name);
    transfer.inputsHash = inputsHash.GetHash();

    CSparkNameTxData transferMessage = transfer;
    transferMessage.addressOwnershipProof.clear();
    transferMessage.transferOwnershipProof.clear();
    CHashWriter nameHash(SER_GETHASH, PROTOCOL_VERSION);
    nameHash << transferMessage;
    CHashWriter transferHash(SER_GETHASH, PROTOCOL_VERSION);
    transferHash << "SparkNameTransferProof";
    transferHash << transfer.oldSparkAddress << transfer.sparkAddress;
    transferHash << nameHash.GetHash();

    const spark::Params* params = spark::Params::get_default();
    spark::SpendKey spendKey =
        pwalletMain->sparkWallet->generateSpendKey(params);
    spark::Address oldAddress(params);
    oldAddress.decode(addressA);
    spark::Scalar transferScalar;
    transferScalar.SetHex(transferHash.GetHash().ToString());
    spark::OwnershipProof transferProof;
    oldAddress.prove_own(
        transferScalar,
        spendKey,
        spark::FullViewKey(spendKey),
        transferProof);
    CDataStream transferProofStream(SER_NETWORK, PROTOCOL_VERSION);
    transferProofStream << transferProof;
    transfer.transferOwnershipProof.assign(
        transferProofStream.begin(), transferProofStream.end());

    CMutableTransaction transferTx = CreateSparkNameTx(transfer, false);
    BOOST_REQUIRE(CTransaction(transferTx).IsSparkSpendV2());
    CValidationState validState;
    BOOST_REQUIRE(CheckTransaction(
        CTransaction(transferTx), validState, false, transferTx.GetHash(),
        false, chainActive.Height() + 1, false, true, nullptr));

    CMutableTransaction tailedTransferProof(transferTx);
    ModifySparkNameTx(
        tailedTransferProof,
        [](CSparkNameTxData& changedData) {
            changedData.transferOwnershipProof.push_back(0);
        },
        false);
    CValidationState tailedState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(tailedTransferProof), tailedState, false,
        tailedTransferProof.GetHash(), false, chainActive.Height() + 1,
        false, true, nullptr));

    const int beforeTransfer = chainActive.Height();
    BOOST_REQUIRE(GenerateBlock({transferTx}));
    BOOST_CHECK_EQUAL(chainActive.Height(), beforeTransfer + 1);
    std::string resolved;
    BOOST_REQUIRE(sparkNameManager->GetSparkAddress(transfer.name, resolved));
    BOOST_CHECK_EQUAL(resolved, transfer.sparkAddress);

    const UniValue historical = CallRPC(
        "getsparknametxdetails " + registrationTx.GetHash().ToString());
    BOOST_CHECK_EQUAL(
        find_value(historical, "address").get_str(), addressA);
    BOOST_CHECK_EQUAL(
        find_value(historical, "validUntil").get_int64(),
        registrationExpiration);
}

BOOST_AUTO_TEST_CASE(unconfirmed_details_report_pending_validity)
{
    Initialize(510);
    const int activationHeight = chainActive.Height() + 1;
    mutableConsensus.nSparkSingleInputStartBlock = activationHeight;
    mutableConsensus.nSparkChaumV2StartBlock = activationHeight;
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;

    CSparkNameTxData registration;
    registration.nVersion = CSparkNameTxData::CURRENT_VERSION;
    registration.name = "pending-details";
    registration.sparkAddress = GenerateSparkAddress();
    registration.sparkNameValidityBlocks = 100;
    CMutableTransaction registrationTx =
        CreateSparkNameTx(registration, true);
    BOOST_REQUIRE(lastState.IsValid());

    const UniValue pendingRegistration = CallRPC(
        "getsparknametxdetails " + registrationTx.GetHash().ToString());
    BOOST_CHECK_EQUAL(
        find_value(pendingRegistration, "validUntil").get_int64(),
        chainActive.Height() + 1 +
            registration.sparkNameValidityBlocks);

    BOOST_REQUIRE(GenerateBlock({registrationTx}));
    const uint64_t existingValidity =
        sparkNameManager->GetSparkNameBlockHeight(registration.name);

    CSparkNameTxData renewal = registration;
    renewal.sparkNameValidityBlocks = 25;
    renewal.additionalInfo = "pending-renewal";
    CMutableTransaction renewalTx = CreateSparkNameTx(renewal, true);
    BOOST_REQUIRE(lastState.IsValid());

    const UniValue pendingRenewal = CallRPC(
        "getsparknametxdetails " + renewalTx.GetHash().ToString());
    BOOST_CHECK_EQUAL(
        find_value(pendingRenewal, "validUntil").get_int64(),
        existingValidity + renewal.sparkNameValidityBlocks);
}

BOOST_AUTO_TEST_CASE(general)
{
    Initialize();
    
    std::string txaddress = GenerateSparkAddress();
    CMutableTransaction tx = CreateSparkNameTx("testname", txaddress, 2, "x", true);
    GenerateBlock({tx});
    BOOST_CHECK(IsSparkNamePresent("testname"));
    GenerateBlock({});
    BOOST_CHECK(IsSparkNamePresent("testname"));
    GenerateBlock({});
    BOOST_CHECK(!IsSparkNamePresent("testname"));
    // invalidate last block
    DisconnectAndInvalidate();
    // spark name should reappear
    BOOST_CHECK(IsSparkNamePresent("testname"));
    DisconnectAndInvalidate();
    // still there
    BOOST_CHECK(IsSparkNamePresent("testname"));
    DisconnectAndInvalidate();
    // should be gone now
    BOOST_CHECK(!IsSparkNamePresent("testname"));

    BOOST_CHECK_EQUAL(mempool.size(), 1);

    std::string tx2address = GenerateSparkAddress();
    CMutableTransaction tx2 = CreateSparkNameTx("testname2", tx2address, 5, "my data", true);
    CreateSparkNameTx("testname", GenerateSparkAddress(), 100, "my data", true);

    // testname2 should get into mempool, testname should not because of mempool conflict
    BOOST_CHECK_EQUAL(mempool.size(), 2);
    BOOST_CHECK_EQUAL(mempool.sparkNames.count("TESTNAME"), 1);
    BOOST_CHECK_EQUAL(mempool.sparkNames.count("TESTNAME2"), 1);
    BOOST_CHECK(!lastState.IsValid());
    BOOST_CHECK_EQUAL(lastState.GetRejectReason(), "txn-mempool-conflict");

    // usage of already used spark address (in mempool) should be rejected
    CreateSparkNameTx("someothername", tx2address, 100, "my data", true);
    BOOST_CHECK(!lastState.IsValid());
    BOOST_CHECK_EQUAL(lastState.GetRejectReason(), "txn-mempool-conflict");

    GenerateBlock({tx, tx2});
    BOOST_CHECK_EQUAL(mempool.size(), 0);
    BOOST_CHECK(mempool.sparkNames.empty());

    BOOST_CHECK(IsSparkNamePresent("testname"));
    BOOST_CHECK(IsSparkNamePresent("testname2"));

    BOOST_CHECK_EQUAL(GetSparkNameAdditionalData("testname"), "x");

    // should fail because of changed address
    CMutableTransaction txmodFail = CreateSparkNameTx("testname", GenerateSparkAddress(), 3, "dataupdate", true);
    BOOST_ASSERT(!lastState.IsValid());

    // modify additional info and extend validity
    CMutableTransaction txmod = CreateSparkNameTx("testname", txaddress, 3, "dataupdate", true);
    BOOST_ASSERT(lastState.IsValid());
    GenerateBlock({txmod});

    BOOST_CHECK_EQUAL(GetSparkNameAdditionalData("testname"), "dataupdate");

    // roll back a block
    DisconnectBlocks(1);
    BOOST_CHECK_EQUAL(GetSparkNameAdditionalData("testname"), "x");

    ReprocessBlocks(1);
    BOOST_CHECK_EQUAL(GetSparkNameAdditionalData("testname"), "dataupdate");
    GenerateBlocks(2);

    // testname should be still there (because of extension)
    BOOST_CHECK(IsSparkNamePresent("testname"));

    // test using the same spark address now
    CMutableTransaction tx3 = CreateSparkNameTx("testname3", txaddress, 3, "x", true);
    BOOST_CHECK(!lastState.IsValid());

    // shouldn't get into the block as well
    int oldHeight = chainActive.Height();
    GenerateBlock({tx3});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // one more block and testname should be gone
    GenerateBlock({});
    BOOST_CHECK(!IsSparkNamePresent("testname"));

    oldHeight = chainActive.Height();
    // tx3 should go ahead now
    GenerateBlock({tx3});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight+1);

    // check insufficient fee
    CMutableTransaction tx4 = CreateSparkNameTx("tt", GenerateSparkAddress(), 3, "x", true, 1*COIN);
    BOOST_CHECK(!lastState.IsValid());
    // check the block is not generated as well
    oldHeight = chainActive.Height();
    GenerateBlock({tx4});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // now check the number of years is calculated correctly and yearly fee is checked
    CMutableTransaction tx5 = CreateSparkNameTx("testname5", GenerateSparkAddress(), 24*24*365*2, "x", true, 2*COIN);
    BOOST_CHECK(lastState.IsValid());

    CMutableTransaction tx6 = CreateSparkNameTx("testname6", GenerateSparkAddress(), 24*24*365*2, "x", true, 1*COIN);
    BOOST_CHECK(!lastState.IsValid());

    // check that address ownership proof is checked
    CMutableTransaction tx7 = CreateSparkNameTx("testname7", GenerateSparkAddress(), 3, "x", false);
    ModifySparkNameTx(tx7, [](CSparkNameTxData &sparkNameData) {
        sparkNameData.addressOwnershipProof[50] ^= 0x01;
    }, false);

    oldHeight = chainActive.Height();
    GenerateBlock({tx7});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // change back the ownership proof but modify the name, the ownership proof should fail again
    ModifySparkNameTx(tx7, [](CSparkNameTxData &sparkNameData) {
        sparkNameData.addressOwnershipProof[50] ^= 0x01;
        sparkNameData.name = "testname8";
    }, false);

    oldHeight = chainActive.Height();
    GenerateBlock({tx7});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // try increasing version to check that verification fails
    CMutableTransaction tx8 = CreateSparkNameTx("testname8", GenerateSparkAddress(), 3, "x", false);
    ModifySparkNameTx(tx8, [](CSparkNameTxData &sparkNameData) {
        sparkNameData.nVersion++;
    }, true);

    oldHeight = chainActive.Height();
    GenerateBlock({tx8});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);
}

BOOST_AUTO_TEST_CASE(hfblocknumber)
{
    Initialize(1000);   // stay below HF block number for a time being

    // This lifecycle test creates several large name payments. Exercise it
    // with V2 enabled so the single-input rule does not make its legacy
    // multi-input wallet setup fail before the Spark Names assertions run.
    mutableConsensus.nSparkSingleInputStartBlock = 1;
    mutableConsensus.nSparkChaumV2StartBlock = 1;

    // Push V2.1 activation past the end of the graceful period so fee-tag
    // requirements don't interfere with the address-transition test below.
    mutableConsensus.nSparkNamesV21StartBlock = INT_MAX;

    int oldHeight =  chainActive.Height();

    std::string txaddress = GenerateSparkAddress();
    CMutableTransaction tx = CreateSparkNameTx("testname", txaddress, 2, "x", true);
    // should get into the mempool as a normal spend
    BOOST_CHECK(mempool.size() == 1);
    GenerateBlock({tx});

    // block should be successfully generated
    BOOST_CHECK_EQUAL(oldHeight+1, chainActive.Height());
    // but the spark name shouldn't be registered
    BOOST_CHECK(!IsSparkNamePresent("testname"));

    GenerateBlocks(1000);

    std::string tx2address = GenerateSparkAddress();
    CMutableTransaction tx2 = CreateSparkNameTx("testname2", txaddress, 2, "x", true);
    // should be in the mempool
    BOOST_CHECK(mempool.size() == 1);
    oldHeight = chainActive.Height();
    GenerateBlock({tx2});
    // block should be successfully generated
    BOOST_CHECK_EQUAL(oldHeight+1, chainActive.Height());
    // and the spark name should be registered
    BOOST_CHECK(IsSparkNamePresent("testname2"));

    // now test transition to new address
    CMutableTransaction txesOldAddress[3] = {
        CreateSparkNameTx("old1", GenerateSparkAddress(), 10000, "x", true),
        CreateSparkNameTx("old2", GenerateSparkAddress(), 10000, "x", true),
        CreateSparkNameTx("old3", GenerateSparkAddress(), 10000, "x", true)
    };
    mempool.clear();

    GenerateBlocks(consensus.stage41StartBlockDevFundAddressChange - chainActive.Height());

    CMutableTransaction txesNewAddress[2] = {
        CreateSparkNameTx("new1", GenerateSparkAddress(), 10000, "x", true),
        CreateSparkNameTx("new2", GenerateSparkAddress(), 10000, "x", true)
    };
    mempool.clear();

    // roll back two blocks
    DisconnectAndInvalidate();
    DisconnectAndInvalidate();

    oldHeight = chainActive.Height();
    GenerateBlock({txesNewAddress[0]});
    // this should fail because of new address used prematurely
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // but the old address should be accepted
    oldHeight = chainActive.Height();
    GenerateBlock({txesOldAddress[0]});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight+1);

    // and retry the new address
    oldHeight = chainActive.Height();
    GenerateBlock({txesNewAddress[0]});
    // now this operation should succeed
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight+1);

    // now try to use the old address again
    oldHeight = chainActive.Height();
    GenerateBlock({txesOldAddress[1]});
    // this still should succeed because of graceful period
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight+1);

    // skip to past the graceful period
    GenerateBlocks(consensus.stage41StartBlockDevFundAddressChange + consensus.stage41SparkNamesGracefulPeriod - chainActive.Height());
    oldHeight = chainActive.Height();
    GenerateBlock({txesOldAddress[2]});
    // should fail now
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // but the new address should work
    oldHeight = chainActive.Height();
    GenerateBlock({txesNewAddress[1]});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight+1);
}

BOOST_AUTO_TEST_CASE(transfer)
{
    constexpr int nBlockPerYear = 365*24*24;

    // regtest: nSparkNamesV2StartBlock = 2500, need to be past it for transfers
    Initialize(2500);

    // --- Register "xfername" with address A ---
    std::string addrA = GenerateSparkAddress();
    CMutableTransaction txReg = CreateSparkNameTx("xfername", addrA, nBlockPerYear * 5, "original", true);
    BOOST_CHECK(lastState.IsValid());
    GenerateBlock({txReg});
    BOOST_CHECK(IsSparkNamePresent("xfername"));

    std::string resolvedAddr;
    BOOST_CHECK(sparkNameManager->GetSparkAddress("xfername", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrA);

    GenerateBlocks(5);

    // --- Transfer "xfername" from address A to address B ---
    std::string addrB = GenerateSparkAddress();

    CSparkNameTxData transferData;
    transferData.nVersion = CSparkNameTxData::CURRENT_VERSION;
    transferData.name = "xfername";
    transferData.sparkAddress = addrB;
    transferData.oldSparkAddress = addrA;
    transferData.sparkNameValidityBlocks = nBlockPerYear;
    transferData.operationType = (uint8_t)CSparkNameTxData::opTransfer;
    transferData.additionalInfo = "transferred";

    // Compute transfer request hash (mirrors requestsparknametransfer RPC)
    {
        CHashWriter nameHash(SER_GETHASH, PROTOCOL_VERSION);
        nameHash << transferData;

        CHashWriter hashStream(SER_GETHASH, PROTOCOL_VERSION);
        hashStream << "SparkNameTransferProof";
        hashStream << transferData.oldSparkAddress << transferData.sparkAddress;
        hashStream << nameHash.GetHash();

        // Create transfer ownership proof using spend key (mirrors transfersparkname RPC)
        const spark::Params *sparkParams = spark::Params::get_default();
        spark::SpendKey spendKey = pwalletMain->sparkWallet->generateSpendKey(sparkParams);

        spark::Address oldAddress(sparkParams);
        oldAddress.decode(addrA);

        spark::Scalar mTransfer;
        mTransfer.SetHex(hashStream.GetHash().ToString());

        spark::OwnershipProof transferProof;
        oldAddress.prove_own(mTransfer, spendKey, spark::FullViewKey(spendKey), transferProof);

        CDataStream proofStream(SER_NETWORK, PROTOCOL_VERSION);
        proofStream << transferProof;
        transferData.transferOwnershipProof.assign(proofStream.begin(), proofStream.end());
    }

    CMutableTransaction txTransfer = CreateSparkNameTx(transferData, true);
    BOOST_CHECK(lastState.IsValid());
    GenerateBlock({txTransfer});

    // Verify name is now at address B
    BOOST_CHECK(IsSparkNamePresent("xfername"));
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("xfername", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrB);
    BOOST_CHECK_EQUAL(GetSparkNameAdditionalData("xfername"), "transferred");

    // Verify old address A is freed and new address B is associated
    std::string nameByAddr;
    BOOST_CHECK(!sparkNameManager->GetSparkNameByAddress(addrA, nameByAddr));
    BOOST_CHECK(sparkNameManager->GetSparkNameByAddress(addrB, nameByAddr));
    BOOST_CHECK_EQUAL(nameByAddr, "xfername");

    // --- Test rollback reverting the transfer ---
    DisconnectBlocks(1);

    BOOST_CHECK(IsSparkNamePresent("xfername"));
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("xfername", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrA);
    BOOST_CHECK_EQUAL(GetSparkNameAdditionalData("xfername"), "original");

    BOOST_CHECK(sparkNameManager->GetSparkNameByAddress(addrA, nameByAddr));
    BOOST_CHECK(!sparkNameManager->GetSparkNameByAddress(addrB, nameByAddr));

    // Re-apply the block and verify transfer is restored
    ReprocessBlocks(1);
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("xfername", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrB);
    BOOST_CHECK_EQUAL(GetSparkNameAdditionalData("xfername"), "transferred");

    // --- Test that invalid transfer proof is rejected ---
    GenerateBlocks(5);
    std::string addrC = GenerateSparkAddress();

    CSparkNameTxData badTransferData;
    badTransferData.nVersion = CSparkNameTxData::CURRENT_VERSION;
    badTransferData.name = "xfername";
    badTransferData.sparkAddress = addrC;
    badTransferData.oldSparkAddress = addrB;
    badTransferData.sparkNameValidityBlocks = nBlockPerYear;
    badTransferData.operationType = (uint8_t)CSparkNameTxData::opTransfer;
    badTransferData.additionalInfo = "bad";
    // Use wrong proof (from previous transfer, bound to a different hash)
    badTransferData.transferOwnershipProof = transferData.transferOwnershipProof;

    CMutableTransaction txBadTransfer = CreateSparkNameTx(badTransferData, false);
    int oldHeight = chainActive.Height();
    GenerateBlock({txBadTransfer});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // Name should still be at address B
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("xfername", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrB);

    // --- Test that transfer with wrong old address is rejected ---
    CSparkNameTxData wrongOldAddrData;
    wrongOldAddrData.nVersion = CSparkNameTxData::CURRENT_VERSION;
    wrongOldAddrData.name = "xfername";
    wrongOldAddrData.sparkAddress = addrC;
    wrongOldAddrData.oldSparkAddress = addrA;  // addrA no longer owns the name
    wrongOldAddrData.sparkNameValidityBlocks = nBlockPerYear;
    wrongOldAddrData.operationType = (uint8_t)CSparkNameTxData::opTransfer;
    wrongOldAddrData.additionalInfo = "wrong old addr";

    // Create a valid-looking proof for addrA (but addrA doesn't own the name anymore)
    {
        CHashWriter nameHash(SER_GETHASH, PROTOCOL_VERSION);
        nameHash << wrongOldAddrData;

        CHashWriter hashStream(SER_GETHASH, PROTOCOL_VERSION);
        hashStream << "SparkNameTransferProof";
        hashStream << wrongOldAddrData.oldSparkAddress << wrongOldAddrData.sparkAddress;
        hashStream << nameHash.GetHash();

        const spark::Params *sparkParams = spark::Params::get_default();
        spark::SpendKey spendKey = pwalletMain->sparkWallet->generateSpendKey(sparkParams);

        spark::Address addrAObj(sparkParams);
        addrAObj.decode(addrA);

        spark::Scalar mTransfer;
        mTransfer.SetHex(hashStream.GetHash().ToString());

        spark::OwnershipProof wrongProof;
        addrAObj.prove_own(mTransfer, spendKey, spark::FullViewKey(spendKey), wrongProof);

        CDataStream proofStream(SER_NETWORK, PROTOCOL_VERSION);
        proofStream << wrongProof;
        wrongOldAddrData.transferOwnershipProof.assign(proofStream.begin(), proofStream.end());
    }

    CMutableTransaction txWrongOldAddr = CreateSparkNameTx(wrongOldAddrData, false);
    oldHeight = chainActive.Height();
    GenerateBlock({txWrongOldAddr});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // Name should still be at address B
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("xfername", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrB);
}

BOOST_AUTO_TEST_CASE(extension_v21)
{
    // regtest: spark names start at 2000, V2.1 starts at 2700
    constexpr int nBlockPerYear = 365*24*24;

    Initialize();
    // we're now at block ~2001

    std::string addr1 = GenerateSparkAddress();

    // Register "exttest" with 1 year validity
    CMutableTransaction txReg = CreateSparkNameTx("exttest", addr1, nBlockPerYear, "initial", true);
    GenerateBlock({txReg});
    BOOST_CHECK(IsSparkNamePresent("exttest"));

    int registrationHeight = chainActive.Height();
    uint64_t originalExpiration = sparkNameManager->GetSparkNameBlockHeight("exttest");
    BOOST_CHECK_EQUAL(originalExpiration, registrationHeight + nBlockPerYear);

    // --- Pre-V2.1: extend the name by 1 year ---
    // Advance some blocks so there's meaningful remaining validity
    GenerateBlocks(100);
    int preV21Height = chainActive.Height();
    BOOST_CHECK(preV21Height < consensus.nSparkNamesV21StartBlock);
    int remainingBeforeExtend = (int)originalExpiration - preV21Height;
    BOOST_CHECK(remainingBeforeExtend > 0);

    CMutableTransaction txExtPre = CreateSparkNameTx("exttest", addr1, nBlockPerYear, "extended-pre", true);
    GenerateBlock({txExtPre});
    BOOST_CHECK(IsSparkNamePresent("exttest"));

    int extendHeightPre = chainActive.Height();
    uint64_t expirationAfterPreV21Extend = sparkNameManager->GetSparkNameBlockHeight("exttest");

    // Before V2.1, remaining validity is NOT preserved — new expiration = extendHeight + newBlocks
    BOOST_CHECK_EQUAL(expirationAfterPreV21Extend, extendHeightPre + nBlockPerYear);
    // The remaining blocks from original registration are lost
    BOOST_CHECK(expirationAfterPreV21Extend < (uint64_t)(extendHeightPre + nBlockPerYear + remainingBeforeExtend));

    // --- Advance to V2.1 ---
    int blocksToV21 = consensus.nSparkNamesV21StartBlock - chainActive.Height();
    BOOST_CHECK(blocksToV21 > 0);
    GenerateBlocks(blocksToV21);
    BOOST_CHECK(chainActive.Height() >= consensus.nSparkNamesV21StartBlock);

    // Name should still be valid (we registered for 1 year = 210240 blocks and only advanced ~700 blocks)
    BOOST_CHECK(IsSparkNamePresent("exttest"));
    uint64_t expirationBeforeV21Extend = sparkNameManager->GetSparkNameBlockHeight("exttest");
    int preV21ExtendHeight = chainActive.Height();
    int remainingBeforeV21Extend = (int)expirationBeforeV21Extend - preV21ExtendHeight;
    BOOST_CHECK(remainingBeforeV21Extend > 0);

    // --- Post-V2.1: extend the name by 1 year ---
    CMutableTransaction txExtPost = CreateSparkNameTx("exttest", addr1, nBlockPerYear, "extended-post", true);
    GenerateBlock({txExtPost});
    BOOST_CHECK(IsSparkNamePresent("exttest"));

    int extendHeightPost = chainActive.Height();
    uint64_t expirationAfterV21Extend = sparkNameManager->GetSparkNameBlockHeight("exttest");

    // After V2.1, remaining validity IS preserved — new expiration = extendHeight + newBlocks + remaining
    int expectedRemaining = (int)expirationBeforeV21Extend - extendHeightPost;
    BOOST_CHECK(expectedRemaining > 0);
    BOOST_CHECK_EQUAL(expirationAfterV21Extend, (uint64_t)(extendHeightPost + nBlockPerYear + expectedRemaining));

    // Verify rollback restores old expiration
    DisconnectBlocks(1);
    BOOST_CHECK(IsSparkNamePresent("exttest"));
    BOOST_CHECK_EQUAL(sparkNameManager->GetSparkNameBlockHeight("exttest"), expirationBeforeV21Extend);

    // Reprocess and verify extension is restored
    ReprocessBlocks(1);
    BOOST_CHECK_EQUAL(sparkNameManager->GetSparkNameBlockHeight("exttest"), expirationAfterV21Extend);
    BOOST_CHECK_EQUAL(GetSparkNameAdditionalData("exttest"), "extended-post");
}

BOOST_AUTO_TEST_CASE(extension_max_validity)
{
    constexpr int nBlockPerYear = 365*24*24;

    // Initialize past V2.1 (regtest V2.1 starts at block 2700)
    Initialize(2700);

    // --- Test 1: Register for exactly 15 years - should succeed ---
    std::string addr1 = GenerateSparkAddress();
    CMutableTransaction txReg15 = CreateSparkNameTx("maxval1", addr1, nBlockPerYear * 15, "", false);
    int oldHeight = chainActive.Height();
    GenerateBlock({txReg15});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1);
    BOOST_CHECK(IsSparkNamePresent("maxval1"));
    int regHeight = chainActive.Height();
    uint64_t exp15 = sparkNameManager->GetSparkNameBlockHeight("maxval1");
    BOOST_CHECK_EQUAL(exp15, (uint64_t)(regHeight + nBlockPerYear * 15));

    // --- Test 2: Try to include a 16-year registration in a block - should be rejected ---
    std::string addr2 = GenerateSparkAddress();
    CMutableTransaction txReg16 = CreateSparkNameTx("maxval2", addr2, nBlockPerYear * 16, "", false);
    oldHeight = chainActive.Height();
    GenerateBlock({txReg16});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight); // block rejected
    BOOST_CHECK(!IsSparkNamePresent("maxval2"));

    // --- Test 3: Register for 10 years, extend by 5 years -> total ~15 years -> should succeed ---
    std::string addr3 = GenerateSparkAddress();
    CMutableTransaction txReg10a = CreateSparkNameTx("maxval3", addr3, nBlockPerYear * 10, "", false);
    oldHeight = chainActive.Height();
    GenerateBlock({txReg10a});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1);
    BOOST_CHECK(IsSparkNamePresent("maxval3"));

    GenerateBlocks(5);

    CMutableTransaction txExt5 = CreateSparkNameTx("maxval3", addr3, nBlockPerYear * 5, "ext5", false);
    oldHeight = chainActive.Height();
    GenerateBlock({txExt5});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1);
    BOOST_CHECK(IsSparkNamePresent("maxval3"));

    // Verify extended expiration preserves remaining time (post-V21 behavior)
    int extHeight = chainActive.Height();
    uint64_t expExt = sparkNameManager->GetSparkNameBlockHeight("maxval3");
    // Total from extend height should be close to 15 years (minus the few blocks advanced)
    BOOST_CHECK(expExt > (uint64_t)(extHeight + nBlockPerYear * 14));
    BOOST_CHECK(expExt <= (uint64_t)(extHeight + nBlockPerYear * 15));

    // --- Test 4: Register for 10 years, try extending by 6 years -> total > 15 years -> should fail ---
    std::string addr4 = GenerateSparkAddress();
    CMutableTransaction txReg10b = CreateSparkNameTx("maxval4", addr4, nBlockPerYear * 10, "", false);
    oldHeight = chainActive.Height();
    GenerateBlock({txReg10b});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1);
    BOOST_CHECK(IsSparkNamePresent("maxval4"));

    CMutableTransaction txExt6 = CreateSparkNameTx("maxval4", addr4, nBlockPerYear * 6, "ext6", false);
    oldHeight = chainActive.Height();
    GenerateBlock({txExt6});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight); // block rejected - total exceeds 15 years
}

BOOST_AUTO_TEST_CASE(tagged_fee_output_must_pay_fee)
{
    constexpr int nBlockPerYear = 365*24*24;

    Initialize(2700);

    std::string addr = GenerateSparkAddress();
    CMutableTransaction tx = CreateSparkNameTx("tagfee", addr, nBlockPerYear, "", false);
    CAmount nameFee = consensus.nSparkNamesFee[std::string("tagfee").size()] * COIN;

    bool modifiedFeeOutput = false;
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (tx.vout[i].scriptPubKey.IsSparkNameFee()) {
            CScript baseScript = GetBaseScriptFromSparkNameFee(tx.vout[i].scriptPubKey);
            tx.vout[i].nValue = 0;
            tx.vout.push_back(CTxOut(nameFee, baseScript));
            modifiedFeeOutput = true;
            break;
        }
    }
    BOOST_REQUIRE(modifiedFeeOutput);
    ModifySparkNameTx(tx, [](CSparkNameTxData &) {}, true);

    int oldHeight = chainActive.Height();
    GenerateBlock({tx});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);
    BOOST_CHECK(!IsSparkNamePresent("tagfee"));
}

BOOST_AUTO_TEST_CASE(extension_mempool_uses_next_block_height)
{
    constexpr int nBlockPerYear = 365*24*24;

    Initialize(2700);

    std::string addr = GenerateSparkAddress();
    CMutableTransaction txReg = CreateSparkNameTx("nextheight", addr, nBlockPerYear * 15, "", false);
    int oldHeight = chainActive.Height();
    GenerateBlock({txReg});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1);

    uint64_t originalExpiration = sparkNameManager->GetSparkNameBlockHeight("nextheight");
    CMutableTransaction txExt = CreateSparkNameTx("nextheight", addr, 1, "one-block-extension", true);
    BOOST_CHECK(lastState.IsValid());

    oldHeight = chainActive.Height();
    GenerateBlock({txExt});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1);
    BOOST_CHECK_EQUAL(sparkNameManager->GetSparkNameBlockHeight("nextheight"), originalExpiration + 1);
}

BOOST_AUTO_TEST_CASE(v2_mempool_spark_name_parse_failure_does_not_score_peer)
{
    constexpr int nBlockPerYear = 365 * 24 * 24;

    Initialize(510);
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;

    CSparkNameTxData nameData;
    nameData.name = "v2boundary";
    nameData.nVersion = 1;
    nameData.sparkAddress = GenerateSparkAddress();
    nameData.sparkNameValidityBlocks = nBlockPerYear;

    // Construct a valid pre-activation V1 Spark Name spend, then remove its
    // optional metadata suffix while retaining the tagged name-fee output. This form is
    // accepted below activation but becomes noncanonical at the boundary.
    CMutableTransaction tx = CreateSparkNameTx(nameData, false);
    spark::SpendTransaction parsedSpend(spark::Params::get_default());
    CSparkNameTxData parsedNameData;
    size_t sparkNameDataPos;
    BOOST_REQUIRE(sparkNameManager->ParseSparkNameTxData(
        tx, parsedSpend, parsedNameData, sparkNameDataPos));
    BOOST_REQUIRE_LT(sparkNameDataPos, tx.vExtraPayload.size());
    tx.vExtraPayload.erase(
        tx.vExtraPayload.begin() + sparkNameDataPos,
        tx.vExtraPayload.end());

    mutableConsensus.nSparkSingleInputStartBlock =
        chainActive.Height() + 1;
    const int activationHeight = chainActive.Height() + 2;
    mutableConsensus.nSparkChaumV2StartBlock = activationHeight;

    bool missingInputs = false;
    CValidationState preActivationState;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(AcceptToMemoryPool(
            mempool,
            preActivationState,
            MakeTransactionRef(tx),
            false,
            &missingInputs));
    }
    BOOST_CHECK(!missingInputs);

    // Keep the transaction out of the block so it can be relayed again by an
    // honest node whose next-block height is now the activation boundary.
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock({}));
    BOOST_REQUIRE_EQUAL(chainActive.Height() + 1, activationHeight);

    missingInputs = false;
    CValidationState mempoolState;
    {
        LOCK(cs_main);
        BOOST_CHECK(!AcceptToMemoryPool(
            mempool,
            mempoolState,
            MakeTransactionRef(tx),
            false,
            &missingInputs));
    }
    int mempoolDoS = -1;
    BOOST_REQUIRE(mempoolState.IsInvalid(mempoolDoS));
    BOOST_CHECK_EQUAL(mempoolDoS, 0);

    // The generic transaction path reaches the second Spark Name check using
    // INT_MAX as its mempool-height sentinel and must be non-punitive too.
    CValidationState genericMempoolState;
    {
        LOCK(cs_main);
        BOOST_CHECK(!CheckTransaction(
            CTransaction(tx),
            genericMempoolState,
            false,
            tx.GetHash(),
            false,
            INT_MAX,
            false,
            true,
            nullptr));
    }
    int genericMempoolDoS = -1;
    BOOST_REQUIRE(genericMempoolState.IsInvalid(genericMempoolDoS));
    BOOST_CHECK_EQUAL(genericMempoolDoS, 0);

    // The same encoding in an authoritative post-activation block remains
    // consensus-invalid and receives the ordinary invalid-block score.
    CValidationState blockState;
    spark::CSparkTxInfo blockInfo;
    {
        LOCK(cs_main);
        BOOST_CHECK(!spark::CheckSparkTransaction(
            tx,
            blockState,
            tx.GetHash(),
            false,
            activationHeight,
            false,
            true,
            &blockInfo));
    }
    int blockDoS = 0;
    BOOST_REQUIRE(blockState.IsInvalid(blockDoS));
    BOOST_CHECK_EQUAL(blockDoS, 100);
}

BOOST_AUTO_TEST_CASE(premature_v2_name_failure_does_not_score_peer)
{
    Initialize(510);
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;
    mutableConsensus.nSparkSingleInputStartBlock =
        chainActive.Height() + 1;
    mutableConsensus.nSparkChaumV2StartBlock =
        chainActive.Height() + 1;

    CSparkNameTxData nameData;
    nameData.name = "premature-v2";
    nameData.sparkAddress = GenerateSparkAddress();
    nameData.sparkNameValidityBlocks = 365 * 24 * 24;
    CMutableTransaction tx = CreateSparkNameTx(nameData, false);
    BOOST_REQUIRE(CTransaction(tx).IsSparkSpendV2());

    ModifySparkNameTx(tx, [](CSparkNameTxData& changedData) {
        changedData.nVersion = CSparkNameTxData::CURRENT_VERSION + 1;
    }, false);
    mutableConsensus.nSparkChaumV2StartBlock =
        chainActive.Height() + 2;

    bool missingInputs = false;
    CValidationState mempoolState;
    {
        LOCK(cs_main);
        BOOST_CHECK(!AcceptToMemoryPool(
            mempool,
            mempoolState,
            MakeTransactionRef(tx),
            false,
            &missingInputs));
    }
    int mempoolDoS = -1;
    BOOST_REQUIRE(mempoolState.IsInvalid(mempoolDoS));
    BOOST_CHECK_EQUAL(mempoolDoS, 0);
}

BOOST_AUTO_TEST_CASE(v2_mempool_nested_name_proof_failure_does_not_score_peer)
{
    constexpr int nBlockPerYear = 365 * 24 * 24;

    Initialize(510);
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;

    CSparkNameTxData nameData;
    nameData.name = "v2proofboundary";
    nameData.nVersion = 1;
    nameData.sparkAddress = GenerateSparkAddress();
    nameData.sparkNameValidityBlocks = nBlockPerYear;

    // A V1 ownership-proof vector may contain an ignored suffix. Keep that
    // historically valid encoding non-punitive when next-block policy first
    // requires the canonical V2 representation.
    CMutableTransaction tx = CreateSparkNameTx(nameData, false);
    BOOST_REQUIRE(CTransaction(tx).IsSparkSpendV1());
    ModifySparkNameTx(tx, [](CSparkNameTxData& changedData) {
        changedData.addressOwnershipProof.push_back(0);
    }, false);

    mutableConsensus.nSparkSingleInputStartBlock =
        chainActive.Height() + 1;
    const int activationHeight = chainActive.Height() + 2;
    mutableConsensus.nSparkChaumV2StartBlock = activationHeight;

    bool missingInputs = false;
    CValidationState preActivationState;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(AcceptToMemoryPool(
            mempool,
            preActivationState,
            MakeTransactionRef(tx),
            false,
            &missingInputs));
    }
    BOOST_CHECK(!missingInputs);

    mempool.clear();
    BOOST_REQUIRE(GenerateBlock({}));
    BOOST_REQUIRE_EQUAL(chainActive.Height() + 1, activationHeight);

    missingInputs = false;
    CValidationState mempoolState;
    {
        LOCK(cs_main);
        BOOST_CHECK(!AcceptToMemoryPool(
            mempool,
            mempoolState,
            MakeTransactionRef(tx),
            false,
            &missingInputs));
    }
    int mempoolDoS = -1;
    BOOST_REQUIRE(mempoolState.IsInvalid(mempoolDoS));
    BOOST_CHECK_EQUAL(mempoolDoS, 0);

    CValidationState blockState;
    spark::CSparkTxInfo blockInfo;
    {
        LOCK(cs_main);
        BOOST_CHECK(!spark::CheckSparkTransaction(
            tx,
            blockState,
            tx.GetHash(),
            false,
            activationHeight,
            false,
            true,
            &blockInfo));
    }
    int blockDoS = 0;
    BOOST_REQUIRE(blockState.IsInvalid(blockDoS));
    BOOST_CHECK_EQUAL(blockDoS, 100);
}

BOOST_AUTO_TEST_CASE(v2_mempool_transfer_proof_failure_does_not_score_peer)
{
    constexpr int nBlockPerYear = 365 * 24 * 24;

    Initialize(510);
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;
    const int singleInputHeight = chainActive.Height() + 1;
    const int activationHeight = chainActive.Height() + 3;
    mutableConsensus.nSparkSingleInputStartBlock = singleInputHeight;
    mutableConsensus.nSparkChaumV2StartBlock = activationHeight;

    const std::string addressA = GenerateSparkAddress();
    CSparkNameTxData registration;
    registration.nVersion = CSparkNameTxData::CURRENT_VERSION;
    registration.name = "v2transferboundary";
    registration.sparkAddress = addressA;
    registration.sparkNameValidityBlocks = nBlockPerYear;
    CMutableTransaction registrationTx =
        CreateSparkNameTx(registration, false);
    BOOST_REQUIRE(CTransaction(registrationTx).IsSparkSpendV1());
    BOOST_REQUIRE(GenerateBlock({registrationTx}));

    CSparkNameTxData transfer;
    transfer.nVersion = CSparkNameTxData::CURRENT_VERSION;
    transfer.operationType = CSparkNameTxData::opTransfer;
    transfer.name = registration.name;
    transfer.oldSparkAddress = addressA;
    transfer.sparkAddress = GenerateSparkAddress();
    transfer.sparkNameValidityBlocks = nBlockPerYear;
    CHashWriter inputsHash(SER_GETHASH, PROTOCOL_VERSION);
    inputsHash << sparkNameManager->GetSparkNameBlockHeight(transfer.name);
    transfer.inputsHash = inputsHash.GetHash();

    CSparkNameTxData transferMessage = transfer;
    transferMessage.addressOwnershipProof.clear();
    transferMessage.transferOwnershipProof.clear();
    CHashWriter nameHash(SER_GETHASH, PROTOCOL_VERSION);
    nameHash << transferMessage;
    CHashWriter transferHash(SER_GETHASH, PROTOCOL_VERSION);
    transferHash << "SparkNameTransferProof";
    transferHash << transfer.oldSparkAddress << transfer.sparkAddress;
    transferHash << nameHash.GetHash();

    const spark::Params* params = spark::Params::get_default();
    spark::SpendKey spendKey =
        pwalletMain->sparkWallet->generateSpendKey(params);
    spark::Address oldAddress(params);
    oldAddress.decode(addressA);
    spark::Scalar transferScalar;
    transferScalar.SetHex(transferHash.GetHash().ToString());
    spark::OwnershipProof transferProof;
    oldAddress.prove_own(
        transferScalar,
        spendKey,
        spark::FullViewKey(spendKey),
        transferProof);
    CDataStream transferProofStream(SER_NETWORK, PROTOCOL_VERSION);
    transferProofStream << transferProof;
    transfer.transferOwnershipProof.assign(
        transferProofStream.begin(), transferProofStream.end());

    CMutableTransaction tx = CreateSparkNameTx(transfer, false);
    BOOST_REQUIRE(CTransaction(tx).IsSparkSpendV1());
    ModifySparkNameTx(tx, [](CSparkNameTxData& changedData) {
        changedData.transferOwnershipProof.push_back(0);
    });

    bool missingInputs = false;
    CValidationState preActivationState;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(AcceptToMemoryPool(
            mempool,
            preActivationState,
            MakeTransactionRef(tx),
            false,
            &missingInputs));
    }
    BOOST_CHECK(!missingInputs);

    mempool.clear();
    BOOST_REQUIRE(GenerateBlock({}));
    BOOST_REQUIRE_EQUAL(chainActive.Height() + 1, activationHeight);

    missingInputs = false;
    CValidationState mempoolState;
    {
        LOCK(cs_main);
        BOOST_CHECK(!AcceptToMemoryPool(
            mempool,
            mempoolState,
            MakeTransactionRef(tx),
            false,
            &missingInputs));
    }
    int mempoolDoS = -1;
    BOOST_REQUIRE(mempoolState.IsInvalid(mempoolDoS));
    BOOST_CHECK_EQUAL(mempoolDoS, 0);

    CValidationState blockState;
    spark::CSparkTxInfo blockInfo;
    {
        LOCK(cs_main);
        BOOST_CHECK(!spark::CheckSparkTransaction(
            tx,
            blockState,
            tx.GetHash(),
            false,
            activationHeight,
            false,
            true,
            &blockInfo));
    }
    int blockDoS = 0;
    BOOST_REQUIRE(blockState.IsInvalid(blockDoS));
    BOOST_CHECK_EQUAL(blockDoS, 100);
}

BOOST_AUTO_TEST_CASE(mempool_name_state_conflict_does_not_score_peer)
{
    Initialize(510);
    const int activationHeight = chainActive.Height() + 1;
    mutableConsensus.nSparkSingleInputStartBlock = activationHeight;
    mutableConsensus.nSparkChaumV2StartBlock = activationHeight;
    mutableConsensus.nSparkNamesStartBlock = 1;
    mutableConsensus.nSparkNamesV2StartBlock = 1;
    mutableConsensus.nSparkNamesV21StartBlock = 1;

    CSparkNameTxData nameData;
    nameData.nVersion = CSparkNameTxData::CURRENT_VERSION;
    nameData.name = "state-conflict";
    nameData.sparkAddress = GenerateSparkAddress();
    nameData.sparkNameValidityBlocks = 100;
    CMutableTransaction tx = CreateSparkNameTx(nameData, false);
    BOOST_REQUIRE(CTransaction(tx).IsSparkSpendV2());

    const std::string competingAddress = GenerateSparkAddress();
    BOOST_REQUIRE(sparkNameManager->AddSparkName(
        nameData.name,
        competingAddress,
        activationHeight + 100,
        ""));

    bool missingInputs = false;
    CValidationState mempoolState;
    {
        LOCK(cs_main);
        BOOST_CHECK(!AcceptToMemoryPool(
            mempool,
            mempoolState,
            MakeTransactionRef(tx),
            false,
            &missingInputs));
    }
    int mempoolDoS = -1;
    BOOST_REQUIRE(mempoolState.IsInvalid(mempoolDoS));
    BOOST_CHECK_EQUAL(mempoolDoS, 0);

    CValidationState blockState;
    spark::CSparkTxInfo blockInfo;
    {
        LOCK(cs_main);
        BOOST_CHECK(!spark::CheckSparkTransaction(
            tx,
            blockState,
            tx.GetHash(),
            false,
            activationHeight,
            false,
            true,
            &blockInfo));
    }
    int blockDoS = 0;
    BOOST_REQUIRE(blockState.IsInvalid(blockDoS));
    BOOST_CHECK_EQUAL(blockDoS, 100);
}

BOOST_AUTO_TEST_CASE(clearing_mempool_clears_spark_name_conflicts)
{
    mempool.sparkNames.emplace(
        "STALE-NAME",
        std::make_pair(std::string(), uint256()));
    BOOST_REQUIRE(!mempool.sparkNames.empty());

    mempool.clear();

    BOOST_CHECK(mempool.sparkNames.empty());
}

BOOST_AUTO_TEST_CASE(validity_overflow_protection)
{
    constexpr int nBlockPerYear = 365*24*24;

    // Initialize past V2.1 (regtest V2.1 starts at 2700)
    Initialize(2700);

    std::string addr1 = GenerateSparkAddress();

    // Register "overtest" with 1 year to have an existing name available for renewal
    CMutableTransaction txReg = CreateSparkNameTx("overtest", addr1, nBlockPerYear, "", true);
    BOOST_CHECK(lastState.IsValid());
    GenerateBlock({txReg});
    BOOST_CHECK(IsSparkNamePresent("overtest"));

    // sparkNameValidityBlocks is uint32_t. Without the explicit uint32_t check, a value
    // above INT_MAX narrows to a negative int, causing the 15-year cap comparison to
    // silently pass. The tests below verify this is now rejected.

    const uint32_t overflowBlocks = (uint32_t)INT_MAX + 1u; // minimal case that triggers the bug

    // --- Fresh registration with sparkNameValidityBlocks = INT_MAX + 1 ---
    std::string addr2 = GenerateSparkAddress();
    CMutableTransaction txNewOverflow = CreateSparkNameTx("newname1", addr2, nBlockPerYear, "", false);
    ModifySparkNameTx(txNewOverflow, [](CSparkNameTxData &data) {
        data.sparkNameValidityBlocks = overflowBlocks;
    });
    int oldHeight = chainActive.Height();
    GenerateBlock({txNewOverflow});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight); // block must be rejected

    // --- Renewal of existing name with sparkNameValidityBlocks = INT_MAX + 1 ---
    CMutableTransaction txUpdateOverflow = CreateSparkNameTx("overtest", addr1, nBlockPerYear, "", false);
    ModifySparkNameTx(txUpdateOverflow, [](CSparkNameTxData &data) {
        data.sparkNameValidityBlocks = overflowBlocks;
    });
    oldHeight = chainActive.Height();
    GenerateBlock({txUpdateOverflow});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight); // block must be rejected

    // --- UINT32_MAX variant ---
    CMutableTransaction txMaxOverflow = CreateSparkNameTx("overtest", addr1, nBlockPerYear, "", false);
    ModifySparkNameTx(txMaxOverflow, [](CSparkNameTxData &data) {
        data.sparkNameValidityBlocks = UINT32_MAX;
    });
    oldHeight = chainActive.Height();
    GenerateBlock({txMaxOverflow});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight); // block must be rejected

    // Sanity: a valid 1-year renewal still goes through after all the failed attempts
    CMutableTransaction txValid = CreateSparkNameTx("overtest", addr1, nBlockPerYear, "ok", false);
    oldHeight = chainActive.Height();
    GenerateBlock({txValid});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1); // block must be accepted
    BOOST_CHECK(IsSparkNamePresent("overtest"));
}

BOOST_AUTO_TEST_CASE(transfer_replay_protection_v21)
{
    constexpr int nBlockPerYear = 365*24*24;

    // regtest: V2.1 starts at block 2700. Past it, every transfer must carry an
    // inputsHash committing to the name's current expiration height. The expiration
    // height is unique per registration cycle, so a transfer proof captured in one
    // cycle becomes unusable once the name's expiration height changes.
    Initialize(2700);
    BOOST_CHECK(chainActive.Height() >= consensus.nSparkNamesV21StartBlock);

    auto inputsHashFor = [](uint64_t expirationHeight) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << expirationHeight;
        return hw.GetHash();
    };

    // Sign a transfer ownership proof for `addrFrom` over `data`. This mirrors the
    // message construction in CheckSparkNameTx (both ownership proofs cleared, then
    // "SparkNameTransferProof" || oldAddr || newAddr || hash(data)). Because the
    // message commits to inputsHash, callers must set inputsHash before signing.
    auto signTransfer = [&](CSparkNameTxData &data, const std::string &addrFrom) {
        CSparkNameTxData copy = data;
        copy.addressOwnershipProof.clear();
        copy.transferOwnershipProof.clear();

        CHashWriter nameHash(SER_GETHASH, PROTOCOL_VERSION);
        nameHash << copy;

        CHashWriter hashStream(SER_GETHASH, PROTOCOL_VERSION);
        hashStream << "SparkNameTransferProof";
        hashStream << data.oldSparkAddress << data.sparkAddress;
        hashStream << nameHash.GetHash();

        const spark::Params *sparkParams = spark::Params::get_default();
        spark::SpendKey spendKey = pwalletMain->sparkWallet->generateSpendKey(sparkParams);

        spark::Address from(sparkParams);
        from.decode(addrFrom);

        spark::Scalar m;
        m.SetHex(hashStream.GetHash().ToString());

        spark::OwnershipProof proof;
        from.prove_own(m, spendKey, spark::FullViewKey(spendKey), proof);

        CDataStream proofStream(SER_NETWORK, PROTOCOL_VERSION);
        proofStream << proof;
        data.transferOwnershipProof.assign(proofStream.begin(), proofStream.end());
    };

    // --- Register "replayname" at address A ---
    std::string addrA = GenerateSparkAddress();
    CMutableTransaction txReg = CreateSparkNameTx("replayname", addrA, nBlockPerYear, "original", true);
    BOOST_CHECK(lastState.IsValid());
    GenerateBlock({txReg});
    BOOST_CHECK(IsSparkNamePresent("replayname"));

    uint64_t expirationA = sparkNameManager->GetSparkNameBlockHeight("replayname");

    // --- Valid transfer A -> B with inputsHash bound to the current expiration height ---
    std::string addrB = GenerateSparkAddress();

    CSparkNameTxData xfer;
    xfer.nVersion = CSparkNameTxData::CURRENT_VERSION;
    xfer.name = "replayname";
    xfer.sparkAddress = addrB;
    xfer.oldSparkAddress = addrA;
    xfer.sparkNameValidityBlocks = nBlockPerYear;
    xfer.operationType = (uint8_t)CSparkNameTxData::opTransfer;
    xfer.additionalInfo = "transferred";
    xfer.inputsHash = inputsHashFor(expirationA);
    signTransfer(xfer, addrA);

    CMutableTransaction txXfer = CreateSparkNameTx(xfer, true);
    BOOST_CHECK(lastState.IsValid());
    int oldHeight = chainActive.Height();
    GenerateBlock({txXfer});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1);

    std::string resolvedAddr;
    BOOST_CHECK(sparkNameManager->GetSparkAddress("replayname", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrB);

    uint64_t expirationB = sparkNameManager->GetSparkNameBlockHeight("replayname");
    std::string addrC = GenerateSparkAddress();

    // Template for a transfer B -> C. Built via the wallet, which fills in inputsHash
    // (bound to the current expiration height) and the destination ownership proof.
    CSparkNameTxData xfer2;
    xfer2.nVersion = CSparkNameTxData::CURRENT_VERSION;
    xfer2.name = "replayname";
    xfer2.sparkAddress = addrC;
    xfer2.oldSparkAddress = addrB;
    xfer2.sparkNameValidityBlocks = nBlockPerYear;
    xfer2.operationType = (uint8_t)CSparkNameTxData::opTransfer;
    xfer2.additionalInfo = "second";
    xfer2.inputsHash = inputsHashFor(expirationB);
    signTransfer(xfer2, addrB);

    // --- A transfer proof bound to a different registration cycle must be rejected ---
    // Build a transfer that is internally consistent (its transfer ownership proof is
    // re-signed over its own inputsHash) but whose inputsHash commits to a *different*
    // expiration height than the name's current one — exactly what a proof captured
    // from another registration cycle would look like. Without the inputsHash check
    // this would be accepted, allowing the replay; with it, it is rejected.
    CMutableTransaction txReplay = CreateSparkNameTx(xfer2, false);
    ModifySparkNameTx(txReplay, [&](CSparkNameTxData &data) {
        data.inputsHash = inputsHashFor(expirationB + 1);   // wrong cycle
        signTransfer(data, data.oldSparkAddress);           // keep the proof consistent
    }, true);

    oldHeight = chainActive.Height();
    GenerateBlock({txReplay});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight); // block rejected
    // name must still be at B
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("replayname", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrB);

    // --- Sanity: the same transfer with inputsHash bound to the current cycle passes ---
    // Confirms the wrong-cycle inputsHash above was the sole reason for rejection.
    CMutableTransaction txValid = CreateSparkNameTx(xfer2, false);
    oldHeight = chainActive.Height();
    GenerateBlock({txValid});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1); // block accepted
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("replayname", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrC);
}

BOOST_AUTO_TEST_CASE(transfer_replay_grace_period_v21)
{
    constexpr int nBlockPerYear = 365*24*24;

    // This test synthesizes pre-v2.1 transfers by mutating extra payload after
    // the wallet builds the spend (nulling inputsHash). Spark V2 spends bind
    // that payload in the proof, so keep Chaum V2 inactive here. The fixture
    // destructor restores the original activation heights.
    mutableConsensus.nSparkSingleInputStartBlock = INT_MAX;
    mutableConsensus.nSparkChaumV2StartBlock = INT_MAX;

    // regtest: V2.1 starts at block 2700 with a 100-block grace period (stage41SparkNamesGracefulPeriod).
    // Transfers built before activation carry no inputsHash; if they were broadcast just before the fork
    // they can still be sitting in the mempool when it activates. During [2700, 2800) such legacy (null
    // inputsHash) transfers remain acceptable so they aren't dropped; from 2800 on, inputsHash is mandatory.
    // The fixture starts at height 100 (TestChain100Setup), so Initialize(2600) lands exactly on the V2.1
    // activation height (2700), at the start of the grace window.
    Initialize(2600);
    BOOST_CHECK(chainActive.Height() >= consensus.nSparkNamesV21StartBlock);
    BOOST_CHECK(chainActive.Height() < consensus.nSparkNamesV21StartBlock + consensus.stage41SparkNamesGracefulPeriod);

    auto inputsHashFor = [](uint64_t expirationHeight) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << expirationHeight;
        return hw.GetHash();
    };

    // Re-sign the transfer ownership proof for `addrFrom` over `data` (see transfer_replay_protection_v21).
    // Because the message commits to inputsHash, this must run after inputsHash has been set on `data`.
    auto signTransfer = [&](CSparkNameTxData &data, const std::string &addrFrom) {
        CSparkNameTxData copy = data;
        copy.addressOwnershipProof.clear();
        copy.transferOwnershipProof.clear();

        CHashWriter nameHash(SER_GETHASH, PROTOCOL_VERSION);
        nameHash << copy;

        CHashWriter hashStream(SER_GETHASH, PROTOCOL_VERSION);
        hashStream << "SparkNameTransferProof";
        hashStream << data.oldSparkAddress << data.sparkAddress;
        hashStream << nameHash.GetHash();

        const spark::Params *sparkParams = spark::Params::get_default();
        spark::SpendKey spendKey = pwalletMain->sparkWallet->generateSpendKey(sparkParams);

        spark::Address from(sparkParams);
        from.decode(addrFrom);

        spark::Scalar m;
        m.SetHex(hashStream.GetHash().ToString());

        spark::OwnershipProof proof;
        from.prove_own(m, spendKey, spark::FullViewKey(spendKey), proof);

        CDataStream proofStream(SER_NETWORK, PROTOCOL_VERSION);
        proofStream << proof;
        data.transferOwnershipProof.assign(proofStream.begin(), proofStream.end());
    };

    // Build a legacy (pre-v2.1) transfer of `name` from `addrFrom` to `addrTo`: the wallet would normally
    // fill in inputsHash for v2.1+, so we null it out and re-sign to reproduce a transfer created before
    // the fork.
    auto buildLegacyTransfer = [&](const std::string &name, const std::string &addrFrom, const std::string &addrTo, const std::string &info) {
        CSparkNameTxData data;
        data.nVersion = CSparkNameTxData::CURRENT_VERSION;
        data.name = name;
        data.sparkAddress = addrTo;
        data.oldSparkAddress = addrFrom;
        data.sparkNameValidityBlocks = nBlockPerYear;
        data.operationType = (uint8_t)CSparkNameTxData::opTransfer;
        data.additionalInfo = info;

        CMutableTransaction tx = CreateSparkNameTx(data, false);
        ModifySparkNameTx(tx, [&](CSparkNameTxData &d) {
            d.inputsHash.SetNull();                 // pre-v2.1: no inputsHash
            signTransfer(d, d.oldSparkAddress);     // keep the transfer proof consistent
        }, true);
        return tx;
    };

    // --- Register "graced" at address A ---
    std::string addrA = GenerateSparkAddress();
    CMutableTransaction txReg = CreateSparkNameTx("graced", addrA, nBlockPerYear, "original", true);
    BOOST_CHECK(lastState.IsValid());
    GenerateBlock({txReg});
    BOOST_CHECK(IsSparkNamePresent("graced"));

    // --- Legacy transfer A -> B (null inputsHash) is accepted while inside the grace period ---
    std::string addrB = GenerateSparkAddress();
    CMutableTransaction txLegacy = buildLegacyTransfer("graced", addrA, addrB, "legacy");

    BOOST_CHECK(chainActive.Height() < consensus.nSparkNamesV21StartBlock + consensus.stage41SparkNamesGracefulPeriod);
    int oldHeight = chainActive.Height();
    GenerateBlock({txLegacy});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1);  // accepted during grace

    std::string resolvedAddr;
    BOOST_CHECK(sparkNameManager->GetSparkAddress("graced", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrB);

    // --- Advance past the grace period; a legacy (null inputsHash) transfer must now be rejected ---
    GenerateBlocks(consensus.nSparkNamesV21StartBlock + consensus.stage41SparkNamesGracefulPeriod - chainActive.Height());
    BOOST_CHECK(chainActive.Height() >= consensus.nSparkNamesV21StartBlock + consensus.stage41SparkNamesGracefulPeriod);

    std::string addrC = GenerateSparkAddress();
    CMutableTransaction txLegacyLate = buildLegacyTransfer("graced", addrB, addrC, "legacy-late");

    oldHeight = chainActive.Height();
    GenerateBlock({txLegacyLate});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);     // rejected after grace
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("graced", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrB);                 // name unchanged, still at B

    // --- Sanity: a proper v2.1 transfer (inputsHash bound to the current expiration height) is still
    // accepted after grace. inputsHash must be set before signing the transfer proof, and matches the
    // value the wallet recomputes in AppendSparkNameTxData. ---
    uint64_t expirationB = sparkNameManager->GetSparkNameBlockHeight("graced");
    CSparkNameTxData xferValid;
    xferValid.nVersion = CSparkNameTxData::CURRENT_VERSION;
    xferValid.name = "graced";
    xferValid.sparkAddress = addrC;
    xferValid.oldSparkAddress = addrB;
    xferValid.sparkNameValidityBlocks = nBlockPerYear;
    xferValid.operationType = (uint8_t)CSparkNameTxData::opTransfer;
    xferValid.additionalInfo = "valid";
    xferValid.inputsHash = inputsHashFor(expirationB);
    signTransfer(xferValid, addrB);
    CMutableTransaction txValid = CreateSparkNameTx(xferValid, false);

    oldHeight = chainActive.Height();
    GenerateBlock({txValid});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight + 1); // accepted after grace
    resolvedAddr.clear();
    BOOST_CHECK(sparkNameManager->GetSparkAddress("graced", resolvedAddr));
    BOOST_CHECK_EQUAL(resolvedAddr, addrC);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(sparkname_static, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ascii_validation)
{
    BOOST_CHECK(CSparkNameManager::IsSparkNameValid("Name-01.test"));
    BOOST_CHECK_EQUAL(CSparkNameManager::ToUpper("Name-01.test"), "NAME-01.TEST");

    const std::string high_byte_name = std::string("spark") + static_cast<char>(0xff);
    BOOST_CHECK(!CSparkNameManager::IsSparkNameValid(high_byte_name));

    const std::string mixed_bytes = std::string("a") + static_cast<char>(0xff) + "z";
    const std::string upper = CSparkNameManager::ToUpper(mixed_bytes);
    BOOST_CHECK_EQUAL(upper[0], 'A');
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(upper[1]), 0xff);
    BOOST_CHECK_EQUAL(upper[2], 'Z');
}

BOOST_AUTO_TEST_SUITE_END()
