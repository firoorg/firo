#include "util.h"

#include <stdint.h>
#include <vector>

#include "chainparams.h"
#include "key.h"
#include "validation.h"
#include "txdb.h"
#include "txmempool.h"
#include "../spark/state.h"
#include "../net.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletexcept.h"
#include "../wallet/coincontrol.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(spark_mintspend, SparkTestingSetup)

BOOST_AUTO_TEST_CASE(spark_mintspend_test)
{
    GenerateBlocks(501);
    pwalletMain->SetBroadcastTransactions(true);

    std::vector<CMutableTransaction> mintTxs;
    GenerateMints({100 * COIN, 60 * COIN}, mintTxs);
    BOOST_CHECK_EQUAL(mempool.size(), mintTxs.size());

    BOOST_REQUIRE(GenerateBlock(mintTxs));
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
    BOOST_REQUIRE(GenerateBlock({}));

    // Construct both transactions before committing either, while the coin is
    // still unspent. Coin control makes their shared input explicit.
    CAmount fee = 0;
    auto firstSpend = pwalletMain->CreateSparkSpendTransaction(
        {{script, 70 * COIN, false}}, {}, fee, nullptr);
    const auto tags = spark::GetSparkUsedTags(*firstSpend.tx);
    BOOST_REQUIRE_EQUAL(tags.size(), 1U);
    COutPoint outPoint;
    BOOST_REQUIRE(spark::GetOutPoint(
        outPoint, pwalletMain->sparkWallet->getCoinFromLTag(tags.front())));
    CCoinControl coinControl;
    coinControl.Select(outPoint);
    auto conflictingSpend = pwalletMain->CreateSparkSpendTransaction(
        {{script, COIN, false}}, {}, fee, &coinControl);
    BOOST_REQUIRE(firstSpend.GetHash() != conflictingSpend.GetHash());
    BOOST_REQUIRE(spark::GetSparkUsedTags(*conflictingSpend.tx) == tags);

    // The conflicting transaction is otherwise valid before the first spend.
    const CBlock validCandidate = CreateBlock(
        {CMutableTransaction(*conflictingSpend.tx)}, script);
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(TestBlockValidity(
            state, Params(), validCandidate, chainActive.Tip()));
    }

    {
        CReserveKey reserveKey(pwalletMain);
        CValidationState state;
        BOOST_REQUIRE(pwalletMain->CommitTransaction(
            firstSpend, reserveKey, g_connman.get(), state, true));
    }
    BOOST_REQUIRE(mempool.exists(firstSpend.GetHash()));
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_CHECK(!AcceptToMemoryPool(
            mempool, state, conflictingSpend.tx, false, nullptr));
        BOOST_REQUIRE(state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "txn-mempool-conflict");
    }
    BOOST_CHECK(!mempool.exists(conflictingSpend.GetHash()));

    BOOST_REQUIRE(GenerateBlock({CMutableTransaction(*firstSpend.tx)}));
    BOOST_REQUIRE_EQUAL(mempool.size(), 0U);

    const CBlock invalidCandidate = CreateBlock(
        {CMutableTransaction(*conflictingSpend.tx)}, script);
    CBlockIndex* const previousTip = chainActive.Tip();

    // Bypass admission to exercise the miner's invalid-mempool guard.
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mempool.addUnchecked(conflictingSpend.GetHash(),
            TestMemPoolEntryHelper().Fee(fee).FromTx(*conflictingSpend.tx)));
    }
    BOOST_CHECK_EXCEPTION(CreateBlock({}, script), std::runtime_error,
        HasReason("TestBlockValidity failed: bad-txns-zerocoin"));
    mempool.clear();

    BOOST_CHECK(ProcessNewBlock(
        Params(), std::make_shared<const CBlock>(invalidCandidate), true, nullptr));
    BOOST_CHECK(chainActive.Tip() == previousTip);
}

BOOST_AUTO_TEST_CASE(spark_limit_test)
{
    GenerateBlocks(1000);
    spark::CSparkState *sparkState = spark::CSparkState::GetState();


    pwalletMain->SetBroadcastTransactions(true);
    // logic
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({500*COIN, 500*COIN, 
        1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN,
        1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN, 1000*COIN,
        3000*COIN, 3000*COIN}, txs);

    int nHeight = chainActive.Height();
    GenerateBlock(txs);
    BOOST_CHECK_EQUAL(chainActive.Tip()->nHeight, nHeight + 1);

    // try spending 700 + 700 (under limit)
    auto spend1 = GenerateSparkSpend({700 * COIN}, {}, nullptr);
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "First SparkSpend not added to mempool");

    auto spend2 = GenerateSparkSpend({700 * COIN}, {}, nullptr);
    BOOST_CHECK_MESSAGE(mempool.size() == 2, "Second SparkSpend not added to mempool");

    int prevHeight = chainActive.Height();
    CBlock block = CreateBlock({CMutableTransaction(spend1), CMutableTransaction(spend2)}, script);
    const CChainParams& chainparams = Params();
    BOOST_CHECK_MESSAGE(ProcessNewBlock(chainparams, std::make_shared<const CBlock>(block), true, NULL), "Block with two spends failed to process");
    BOOST_CHECK_EQUAL(chainActive.Height(), prevHeight + 1);

    // try spending 800 + 800 (over limit)
    auto spend3 = GenerateSparkSpend({800 * COIN}, {}, nullptr);
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "First 800 FIRO SparkSpend not added to mempool");

    auto spend4 = GenerateSparkSpend({800 * COIN}, {}, nullptr);
    BOOST_CHECK_MESSAGE(mempool.size() == 2, "Second 800 FIRO SparkSpend not added to mempool");

    prevHeight = chainActive.Height();
    CBlock block2 = CreateBlock({CMutableTransaction(spend3), CMutableTransaction(spend4)}, script);
    BOOST_CHECK_MESSAGE(!ProcessNewBlock(chainparams, std::make_shared<const CBlock>(block2), true, NULL), "Block with two 800 FIRO spends should not be processed");
    BOOST_CHECK_EQUAL(chainActive.Height(), prevHeight);
    mempool.clear();

    BOOST_CHECK_THROW(GenerateSparkSpend({1100 * COIN}, {}, nullptr), std::runtime_error);
    // Check that the spend of 1100 FIRO has not made it into the mempool
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "1100 FIRO SparkSpend should not be added to mempool");

    // advance to block 1500 so new limits are applied
    GenerateBlocks(1500 - chainActive.Height());
    // After block 1500, limits should be updated, so try spending 800 + 800 again
    int postLimitHeight = chainActive.Height();
    CBlock block4 = CreateBlock({spend3, spend4}, script);
    BOOST_CHECK_MESSAGE(ProcessNewBlock(chainparams, std::make_shared<const CBlock>(block4), true, NULL), "Block with two 800 FIRO spends after limit update failed to process");
    BOOST_CHECK_EQUAL(chainActive.Height(), postLimitHeight + 1);

    BOOST_CHECK_THROW(GenerateSparkSpend({3100 * COIN}, {}, nullptr), std::runtime_error);
    // Check that the spend of 3100 FIRO has not made it into the mempool
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "3100 FIRO SparkSpend should not be added to mempool");

    auto spend7 = GenerateSparkSpend({2500 * COIN}, {}, nullptr);
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "First 2500 FIRO SparkSpend not added to mempool");

    auto spend8 = GenerateSparkSpend({2500 * COIN}, {}, nullptr);
    BOOST_CHECK_MESSAGE(mempool.size() == 2, "Second 2500 FIRO SparkSpend not added to mempool");

    prevHeight = chainActive.Height();
    CBlock block6 = CreateBlock({CMutableTransaction(spend7), CMutableTransaction(spend8)}, script);
    BOOST_CHECK_MESSAGE(!ProcessNewBlock(chainparams, std::make_shared<const CBlock>(block6), true, NULL), "Block with two 2500 FIRO spends should not be processed");
    BOOST_CHECK_EQUAL(chainActive.Height(), prevHeight);

    mempool.clear();
    sparkState->Reset();    
}


    BOOST_AUTO_TEST_SUITE_END()
