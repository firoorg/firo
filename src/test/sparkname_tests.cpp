#include "../chainparams.h"
#include "../script/standard.h"
#include "../validation.h"
#include "../wallet/coincontrol.h"
#include "../wallet/wallet.h"
#include "../net.h"
#include "../sparkname.h"

#include "test_bitcoin.h"
#include "fixtures.h"
#include <iostream>
#include <boost/test/unit_test.hpp>

namespace spark {

class SparkNameTests : public SparkTestingSetup
{
public:
    SparkNameTests() :
          SparkTestingSetup(),
          sparkState(CSparkState::GetState()),
          consensus(::Params().GetConsensus()),
          sparkNameManager(CSparkNameManager::GetInstance()) {
    }

    ~SparkNameTests() {
       sparkState->Reset();
    }

    bool IsSparkNamePresent(std::string const &name) {
        std::string address;
        return sparkNameManager->GetSparkAddress(name, address);
    }

    std::string GetSparkNameAdditionalData(const std::string &name) {
        BOOST_CHECK(IsSparkNamePresent(name));
        return sparkNameManager->GetSparkNameAdditionalData(name);
    }

    void Initialize() {
        std::vector<CMutableTransaction> mintTxs;
        GenerateBlocks(2000-1);
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
        size_t additionalSize = sparkNameManager->GetSparkNameTxDataSize(sparkNameData);

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
        sparkNameData.sparkAddress = address;
        sparkNameData.sparkNameValidityBlocks = sparkNameValidityHeight;
        sparkNameData.additionalInfo = additionalInfo;

        return CreateSparkNameTx(sparkNameData, fCommit, sparkNameFee);
    }

    void DisconnectAndInvalidate() {
        LOCK(cs_main);
        CBlockIndex *pindex = chainActive.Tip();
        DisconnectBlocks(1);
        CValidationState state;
        const CChainParams &chainparams = ::Params();
        InvalidateBlock(state, chainparams, pindex);
    }

    void ModifySparkNameTx(CMutableTransaction &tx, std::function<void(CSparkNameTxData &)> modify) {
        const spark::Params *params = spark::Params::get_default();
        spark::SpendTransaction sparkTx(params);

        CSparkNameTxData sparkNameData;
        size_t sparkNameDataPos;
        BOOST_CHECK(sparkNameManager->ParseSparkNameTxData(tx, sparkTx, sparkNameData, sparkNameDataPos));

        modify(sparkNameData);

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
    });

    oldHeight = chainActive.Height();
    GenerateBlock({tx7});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);

    // change back the ownership proof but modify the name, the ownership proof should fail again
    ModifySparkNameTx(tx7, [](CSparkNameTxData &sparkNameData) {
        sparkNameData.addressOwnershipProof[50] ^= 0x01;
        sparkNameData.name = "testname8";
    });

    oldHeight = chainActive.Height();
    GenerateBlock({tx7});
    BOOST_CHECK_EQUAL(chainActive.Height(), oldHeight);
}

BOOST_AUTO_TEST_SUITE_END()