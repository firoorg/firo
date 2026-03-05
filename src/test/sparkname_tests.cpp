#include "../chainparams.h"
#include "../script/standard.h"
#include "../validation.h"
#include "../wallet/coincontrol.h"
#include "../wallet/wallet.h"
#include "../net.h"
#include "../sparkname.h"

#include "compat_layer.h"
#include "test_bitcoin.h"
#include "fixtures.h"
#include <iostream>
#include <boost/test/unit_test.hpp>

namespace spark {

class SparkNameTests : public SparkTestingSetup
{
private:
    Consensus::Params &mutableConsensus;
    Consensus::Params oldConsensus;

public:
    SparkNameTests() :
          SparkTestingSetup(),
          mutableConsensus(const_cast<Consensus::Params &>(::Params().GetConsensus())),
          sparkState(CSparkState::GetState()),
          consensus(::Params().GetConsensus()),
          sparkNameManager(CSparkNameManager::GetInstance()) {
        oldConsensus = mutableConsensus;
    }

    ~SparkNameTests() {
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
        GenerateMints({50 * COIN, 60 * COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN, 10*COIN}, mintTxs);
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
            for (uint32_t n=0; ; n++) {
                sparkNameData.addressOwnershipProof.clear();
                sparkNameData.hashFailsafe = n;
        
                CMutableTransaction txCopy(tx);
                CDataStream serializedSparkNameData(SER_NETWORK, PROTOCOL_VERSION);
                serializedSparkNameData << sparkNameData;
                txCopy.vExtraPayload.erase(txCopy.vExtraPayload.begin() + sparkNameDataPos, txCopy.vExtraPayload.end());
                txCopy.vExtraPayload.insert(txCopy.vExtraPayload.end(), serializedSparkNameData.begin(), serializedSparkNameData.end());
        
                CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
                ss << txCopy;
        
                spark::Scalar m;
                try {
                    m.SetHex(ss.GetHash().ToString());
                }
                catch (const std::exception &) {
                    continue;   // increase hashFailSafe and try again
                }
        
                spark::Address sparkAddress(spark::Params::get_default());
                spark::OwnershipProof ownershipProof;
        
                spark::SpendKey spendKey = pwalletMain->sparkWallet->generateSpendKey(spark::Params::get_default());
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

    const auto &params = Params().GetConsensus();
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

BOOST_AUTO_TEST_SUITE_END()