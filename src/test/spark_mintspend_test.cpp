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
    GenerateBlocks(1001);
    spark::CSparkState *sparkState = spark::CSparkState::GetState();

    pwalletMain->SetBroadcastTransactions(true);

    std::vector<CMutableTransaction> mintTxs;
    auto sparkMints = GenerateMints({50 * COIN, 60 * COIN}, mintTxs);

    // Verify Mint gets in the mempool
    BOOST_CHECK_MESSAGE(mempool.size() == sparkMints.size(), "Mints were not added to mempool");

    int previousHeight = chainActive.Height();
    auto blockIdx1 = GenerateBlock(mintTxs);
    BOOST_CHECK(blockIdx1);

    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mints were not removed from mempool");
    previousHeight = chainActive.Height();

    CPubKey pub;
    {
        LOCK(pwalletMain->cs_wallet);
        pub = pwalletMain->GenerateNewKey();
    }

    std::vector<CRecipient> recipients = {{GetScriptForDestination(pub.GetID()), 1 * COIN, false}};

    GenerateBlock({});
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool must be empty");

    auto wtx = GenerateSparkSpend({70 * COIN}, {}, nullptr);
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "SparkSpend is not added into mempool");

    previousHeight = chainActive.Height();
    GenerateBlock({CMutableTransaction(wtx)});
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "SparkSpend is not removed from mempool");
    GenerateBlocks(6);

    CAmount fee;
    auto result = pwalletMain->CreateSparkSpendTransaction(recipients, {}, fee, nullptr);
    CWallet* wallet = pwalletMain;
    CReserveKey reserveKey(wallet);
    CValidationState state;
    pwalletMain->CommitTransaction(result, reserveKey, g_connman.get(), state);

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "SparkSpend was not added to mempool");

    //try double spend
    pwalletMain->CommitTransaction(result, reserveKey, g_connman.get(), state);
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Double spend was added into mempool, but was not supposed");

    previousHeight = chainActive.Height();
    GenerateBlock({CMutableTransaction(*result.tx)});
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
    GenerateBlocks(2);

    auto tempTags = sparkState->usedLTags;
    sparkState->usedLTags.clear();

    {
         //Set mints unused, and try to spend again
         for(auto ltag : tempTags)
             pwalletMain->sparkWallet->setCoinUnused(ltag.first);

         spark::Coin coin = pwalletMain->sparkWallet->getCoinFromLTag(tempTags.begin()->first);
         COutPoint outPoint;
         spark::GetOutPoint(outPoint, coin);
         CCoinControl coinControl;
         coinControl.Select(outPoint);

         CAmount fee;
         result.Init(NULL);
         result = pwalletMain->CreateSparkSpendTransaction(recipients, {}, fee, &coinControl);
         CReserveKey reserveKey(pwalletMain);
         CValidationState state;
         pwalletMain->CommitTransaction(result, reserveKey, g_connman.get(), state);

         BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");
    }
    
    sparkState->usedLTags = tempTags;
    BOOST_CHECK_EXCEPTION(GenerateBlock({CMutableTransaction(*result.tx)}), std::runtime_error, no_check);
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not set");
    tempTags = sparkState->usedLTags;
    sparkState->usedLTags.clear();
    CBlock b = CreateBlock({CMutableTransaction(*result.tx)}, script);

    sparkState->usedLTags = tempTags;
    mempool.clear();
    previousHeight = chainActive.Height();

    const CChainParams& chainparams = Params();
    BOOST_CHECK_MESSAGE(ProcessNewBlock(chainparams, std::make_shared<const CBlock>(b), true, NULL), "ProcessBlock failed");
    //This test confirms that a block containing a double spend is rejected and not added in the chain
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Double spend - Block added to chain even though same spend in previous block");

    mempool.clear();
    sparkState->Reset();
}
    BOOST_AUTO_TEST_SUITE_END()
