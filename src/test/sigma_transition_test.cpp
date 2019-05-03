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
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
    string denomination;
    vector<uint256> vtxid;

    denomination = "1";
    string stringError;
    // Make sure that transactions get to mempool
    pwalletMain->SetBroadcastTransactions(true);

    // Try to create a sigma mint. It must not be added to the mempool, because
    // Sigma is enabled at block "nMintV3SigmaStartBlock=400 for regtest".
    vector<pair<std::string, int>> denominationPairs;
    std::pair<std::string, int> denominationPair(denomination, 1);
    denominationPairs.push_back(denominationPair);

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    // Create a zerocoin mint, it must still pass.
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, ZEROCOIN), stringError + " - Create Mint failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

    // Sigma mints must also pass.
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 2, "Mint was not added to mempool");

    // Both transactions must be able to be added to the next block.
    int previousHeight = chainActive.Height();
    CBlock b = CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Expected empty mempool.");

    // Create some zerocoin mints.
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, ZEROCOIN), stringError + " - Create Mint failed");
    }
    BOOST_CHECK_MESSAGE(mempool.size() == 5, "Mint was not added to mempool");

    vtxid.clear();
    mempool.queryHashes(vtxid);
    vtxid.resize(1);

    // Process one more block. After this one, old zerocoin mints must not be allowed to mempool
    // any more, because for regtest consensus.nMintV2MempoolGracefulPeriod = 2.
    previousHeight = chainActive.Height();

    b = CreateAndProcessBlock(vtxid, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

    // Now this new mint must not be added to the mempool any more,
    // because consensus.nMintV2MempoolGracefulPeriod = 2;
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, ZEROCOIN), stringError + " - Create Mint failed");

    // Check that mempool size did not change, so this mint was not added.
    BOOST_CHECK_MESSAGE(mempool.size() == 4, "Mint was added to mempool, but not expected to.");

    // Create 1 more block. All the mints must pass.
    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

    // Check that mempool got empty.
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool did not get empty.");

    // Create 5 more empty blocks, so mints can be spent.
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    // Add an old spend to mempool.
    BOOST_CHECK_MESSAGE(
        pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), false, true),
        "Spend not added to the mempool.");

    // Create a block containing old spend and try to add it to the chain.
    CBlock block = CreateBlock({}, scriptPubKey);

    // Create 5 more empty blocks, such that nZerocoinV2SpendStopBlock = 410 passes.
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    // Create an old spend, it must not be added to the mempool,
    // since nZerocoinV2SpendStopBlock = 410 have passed.
    BOOST_CHECK_MESSAGE(
        pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), false, true),
        "Spend not added to the mempool.");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Spend added to the mempool, but must not be added.");

    // Create 10 more empty blocks, such that nZerocoinV2SpendStopBlockInBlocks = 420 passes.
    CreateAndProcessEmptyBlocks(10, scriptPubKey);

    previousHeight = chainActive.Height();
    ProcessBlock(block);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(),
        "Block added to chain, but must have been rejected.");

    vtxid.clear();
    mempool.clear();
    zerocoinState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
