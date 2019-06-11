#include "util.h"

#include <stdint.h>
#include <vector>

#include "chainparams.h"
#include "key.h"
#include "main.h"
#include "pubkey.h"
#include "txdb.h"
#include "txmempool.h"
#include "zerocoin_v3.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(sigma_transition, ZerocoinTestingSetup200)

/*
* 1. Create one denomination pair and check it can't be spend till 6 conf of mint
* 2. Make one more mint of denom pair and check it can't be spend till 6 conf
* 3. Create two spend transactions using same mint
* 4. Double spend with previous spend in last block
*/
BOOST_AUTO_TEST_CASE(sigma_transition_test)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    string denomination;
    vector<uint256> vtxid;

    denomination = "1";
    string stringError;
    // Make sure that transactions get to mempool
    pwalletMain->SetBroadcastTransactions(true);

    vector<pair<std::string, int>> denominationPairs;
    std::pair<std::string, int> denominationPair(denomination, 2);
    denominationPairs.push_back(denominationPair);

    // Try to mint before activation block it should success but not added to sigma state.
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

    int previousHeight = chainActive.Height();
    CreateAndProcessBlock({}, scriptPubKey);

    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Expected empty mempool.");
    BOOST_CHECK_EQUAL(zerocoinState->GetTotalCoins(), 0);

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    // Mint a new one this one should added to sigma state.
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

    previousHeight = chainActive.Height();
    CreateAndProcessBlock({}, scriptPubKey);

    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Expected empty mempool.");
    BOOST_CHECK_EQUAL(zerocoinState->GetTotalCoins(), 2);

    // Create 5 more empty blocks to be able for mint to spend.
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    CWalletTx tx;
    pwalletMain->SpendZerocoinV3({CRecipient{.scriptPubKey = scriptPubKey, .nAmount = COIN, .fSubtractFeeFromAmount = false}}, tx);
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

    previousHeight = chainActive.Height();
    CreateAndProcessBlock({}, scriptPubKey);

    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Expected empty mempool.");

    mempool.clear();
    sigmaState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
