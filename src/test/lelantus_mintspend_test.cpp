#include "util.h"

#include <stdint.h>
#include <vector>

#include "chainparams.h"
#include "key.h"
#include "validation.h"
#include "pubkey.h"
#include "txdb.h"
#include "txmempool.h"
#include "lelantus.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletexcept.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(lelantus_mintspend, LelantusTestingSetup)

BOOST_AUTO_TEST_CASE(lelantus_mintspend_test)
{
    GenerateBlocks(1000);

    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();

    // Make sure that transactions get to mempool
    pwalletMain->SetBroadcastTransactions(true);

    std::vector<CMutableTransaction> mintTxs;
    auto hdMints = GenerateMints({50 * COIN, 60 * COIN}, mintTxs);

    // Verify Mint gets in the mempool
    BOOST_CHECK_MESSAGE(mempool.size() == hdMints.size(), "Mints were not added to mempool");

    int previousHeight = chainActive.Height();
    auto blockIdx1 = GenerateBlock(mintTxs);
    BOOST_CHECK(blockIdx1);

    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mints were not removed from mempool");
    previousHeight = chainActive.Height();

    // Generate address
    CPubKey newKey;
    BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey), "Fail to get new address");

    const CBitcoinAddress randomAddr(newKey.GetID());
    std::vector<CRecipient> recipients = {
        {GetScriptForDestination(randomAddr.Get()), 30 * COIN, true},
    };

    // Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
    for (int i = 0; i < 5; i++)
    {
        {
            CWalletTx wtx;
            BOOST_CHECK_THROW(pwalletMain->JoinSplitLelantus(recipients, {}, wtx), WalletError); //this must throw as it has to have at least two mint coins with at least 6 confirmation
        }

        GenerateBlock({});
    }

    BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool must be empty");

    CWalletTx wtx;
    {
        BOOST_CHECK_NO_THROW(pwalletMain->JoinSplitLelantus(recipients, {}, wtx)); //this must pass
    }
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "JoinSplit is not added into mempool");

    previousHeight = chainActive.Height();
    GenerateBlock({CMutableTransaction(*wtx.tx)});
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "JoinSplit is not removed from mempool");
    GenerateBlocks(6);
    std::vector<CLelantusEntry> spendCoins; //spends
    std::vector<CSigmaEntry> sigmaSpendCoins;
    CWalletTx result;
    {
        std::vector<CHDMint> mintCoins; // new mints
        CAmount fee;
        result = pwalletMain->CreateLelantusJoinSplitTransaction(recipients, fee, {}, spendCoins, sigmaSpendCoins, mintCoins);
        pwalletMain->CommitLelantusTransaction(result, spendCoins, sigmaSpendCoins, mintCoins);
    }
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Joinsplit was not added to mempool");

    //Set mints unused, and try to spend again
    for(auto mint : spendCoins)
        pwalletMain->zwallet->GetTracker().SetLelantusPubcoinNotUsed(primitives::GetPubCoinValueHash(mint.value));

    wtx.Init(NULL);
    //try double spend
    BOOST_CHECK_NO_THROW(pwalletMain->JoinSplitLelantus(recipients, {}, wtx));
    //Verify spend got into mempool
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Double spend was added into mempool, but was not supposed");

    previousHeight = chainActive.Height();
    GenerateBlock({CMutableTransaction(*result.tx)});
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
    GenerateBlocks(6);
    for(auto mint : spendCoins)
        pwalletMain->zwallet->GetTracker().SetLelantusPubcoinUsed(primitives::GetPubCoinValueHash(mint.value), uint256());

    spendCoins.clear(); //spends
    result.Init(NULL);
    {
        std::vector<CHDMint> mintCoins; // new mints
        CAmount fee;
        result = pwalletMain->CreateLelantusJoinSplitTransaction(recipients, fee, {}, spendCoins, sigmaSpendCoins, mintCoins);
        pwalletMain->CommitLelantusTransaction(result, spendCoins, sigmaSpendCoins, mintCoins);
    }

    //Verify spend got into mempool
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

    previousHeight = chainActive.Height();
    GenerateBlock({CMutableTransaction(*result.tx)});
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
    GenerateBlocks(6);

    //Set mints unused, and try to spend again
    for(auto mint : spendCoins)
        pwalletMain->zwallet->GetTracker().SetLelantusPubcoinNotUsed(primitives::GetPubCoinValueHash(mint.value));
    //try double spend
    wtx.Init(NULL);

    BOOST_CHECK_NO_THROW(pwalletMain->JoinSplitLelantus(recipients, {}, wtx));
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not empty although mempool should reject double spend");

    //Temporary disable usedCoinSerials check to force double spend in mempool
    auto tempSerials = lelantusState->containers.usedCoinSerials;
    lelantusState->containers.usedCoinSerials.clear();

    {
        //Set mints unused, and try to spend again
        for(auto mint : spendCoins)
            pwalletMain->zwallet->GetTracker().SetLelantusPubcoinNotUsed(primitives::GetPubCoinValueHash(mint.value));
        wtx.Init(NULL);
        BOOST_CHECK_NO_THROW(pwalletMain->JoinSplitLelantus(recipients, {}, wtx));
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");
    }

    lelantusState->containers.usedCoinSerials = tempSerials;

    BOOST_CHECK_EXCEPTION(CreateBlock({CMutableTransaction(*wtx.tx)}, script), std::runtime_error, no_check);
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not set");
    tempSerials = lelantusState->containers.usedCoinSerials;
    lelantusState->containers.usedCoinSerials.clear();
    CBlock b = CreateBlock({CMutableTransaction(*wtx.tx)}, script);

    lelantusState->containers.usedCoinSerials = tempSerials;

    mempool.clear();
    previousHeight = chainActive.Height();

    const CChainParams& chainparams = Params();
    BOOST_CHECK_MESSAGE(ProcessNewBlock(chainparams, std::make_shared<const CBlock>(b), true, NULL), "ProcessBlock failed");
    //This test confirms that a block containing a double spend is rejected and not added in the chain
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Double spend - Block added to chain even though same spend in previous block");

    mempool.clear();
    lelantusState->Reset();
}
BOOST_AUTO_TEST_SUITE_END()