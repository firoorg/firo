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

BOOST_FIXTURE_TEST_SUITE(sigma_invalid_spend_proof_test, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(sigma_invalid_spend_proof_test)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    string denomination;

    denomination = "1";
    string stringError;
    // Make sure that transactions get to mempool
    pwalletMain->SetBroadcastTransactions(true);

    vector<pair<std::string, int>> denominationPairs;
    std::pair<std::string, int> denominationPair(denomination, 2);
    denominationPairs.push_back(denominationPair);

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

    int previousHeight = chainActive.Height();
    CBlock b = CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Expected empty mempool.");

    // Create 6 more empty blocks, for mints to mature.
    CreateAndProcessEmptyBlocks(6, scriptPubKey);

    // Create a valid sigma spend.
    BOOST_CHECK_MESSAGE(
        pwalletMain->CreateSigmaSpendModel(stringError, "", denomination.c_str()),
        "Spend not added to the mempool.");

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Valid Spend not added to the mempool.");

    // Create an invalid sigma spend with a wrong spend proof.
    BOOST_CHECK_MESSAGE(
        pwalletMain->CreateSigmaSpendModel(
            stringError, // output parameter for errors.
            "", // thirdPartyAddress
            denomination.c_str(),
            false, // forceUsed
            true   // create_invalid_spend_proof_for_test
        ), "Spend not added to the mempool.");

    BOOST_CHECK_MESSAGE(mempool.size() == 2, "Spend with invalid proof not added to the mempool, but it must have been adeded since we don't check proof while adding to mempool.");

    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend with invalid proof added to the block.");

    mempool.clear();
    sigmaState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
