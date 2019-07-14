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
    FakeTestnet fakeTestnet;

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    string denomination;
    vector<uint256> vtxid;

    denomination = "1";
    string stringError;
    // Make sure that transactions get to mempool
    pwalletMain->SetBroadcastTransactions(true);

    // Try to create a sigma mint. It must not be added to the mempool, because
    // Sigma is enabled at block "nMintV3SigmaStartBlock=400 for regtest".
    vector<pair<std::string, int>> denominationPairs;
    std::pair<std::string, int> denominationPair(denomination, 2);
    denominationPairs.push_back(denominationPair);

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    // Create a zerocoin mint, it must not pass.
    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, ZEROCOIN), "Zerocoin mint creation is success");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mint was added to mempool");

    // Sigma mints must pass.
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

    // a sigma mint transaction must be able to be added to the next block.
    int previousHeight = chainActive.Height();
    CBlock b = CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Expected empty mempool.");

    // Create 5 more empty blocks, so mints can be spent.
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    // Try to spend zerocoin should fail.
    BOOST_CHECK_MESSAGE(
        !pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), false, true),
        "Create zerocoin spend is success.");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Zerocoin spend was added to mempool");

    // Try to spend zerocoin should be success.
    CWalletTx wtx;
    std::string thirdPartyAddress = "TXYb6pEWBDcxQvTxbFQ9sEV1c3rWUPGW3v";
    vector<string> denominationsForTx = {denomination};
    BOOST_CHECK_MESSAGE(
        pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx),
        stringError + " - Spend failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Sigma spend was not added to mempool");

    previousHeight = chainActive.Height();
    CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Expected empty mempool.");

    vtxid.clear();
    mempool.clear();
    sigmaState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()