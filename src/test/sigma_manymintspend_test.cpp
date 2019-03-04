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

BOOST_FIXTURE_TEST_SUITE(sigma_mintspend_many, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(sigma_mintspend_many)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    std::vector<std::string> denominations = {"0.1", "0.5", "1", "10", "100"};

    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();

    pwalletMain->SetBroadcastTransactions(true);

    vector<pair<std::string, int>> denominationPairs;

    for(int i = 0; i < 4; i++)
    {
        thirdPartyAddress = "";
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        denominationsForTx.push_back(denominations[i+1]);
        printf("Testing denominations %s and %s\n",
               denominationsForTx[0].c_str(), denominationsForTx[1].c_str());
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);
        denominationPairs.clear();
        //Verify Mint is successful
        for(int i = 0; i < 2; ++i) {
             std::pair<std::string, int> denominationPair(denominationsForTx[i], 1);
             denominationPairs.push_back(denominationPair);
        }

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");

        // Verify mint tx get added in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");

        int previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        previousHeight = chainActive.Height();
        wtx.Init(NULL);
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");

            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKey);
            wtx.Init(NULL);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        wtx.Init(NULL);
        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(
            wtx, stringError, thirdPartyAddress, denominationsForTx),
            "Spend succeeded although not at least two mints");
        BOOST_CHECK_MESSAGE(
            stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin",
            stringError + " - Incorrect error message");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, SIGMA), stringError + "Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");

        MinTxns.clear();

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");


        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        wtx.Init(NULL);
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");
            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKey);
            wtx.Init(NULL);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        // Create two spend transactions using the same mints
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
        BOOST_CHECK_MESSAGE(wtx.vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.vout.size() == 1, "Incorrect output size");
        wtx.Init(NULL);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx, true), stringError + " - Spend failed");

//        Try to put two in the same block and it will fail, expect 1
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends was not added to mempool");

        vtxid.clear();
        MinTxns.clear();

        b = CreateBlock(MinTxns, scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), stringError + " - Spend failed");
        BOOST_CHECK_MESSAGE(wtx.vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.vout.size() == 1, "Incorrect output size");

        //Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        MinTxns.clear();

        b = CreateBlock(MinTxns, scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
        wtx.Init(NULL);
        //Test double spend with previous spend in last block
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx, true), "Spend created although double");
        //This confirms that double spend is blocked and cannot enter mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not empty although mempool should reject double spend");

        //Temporary disable usedCoinSerials check to force double spend in mempool
        auto tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();

        wtx.Init(NULL);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx, true), "Spend created although double");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mempool not set after used coin serials removed");
        zerocoinState->usedCoinSerials = tempSerials;

        MinTxns.clear();
        BOOST_CHECK_EXCEPTION(CreateBlock(MinTxns, scriptPubKey), std::runtime_error, no_check);
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mempool not set after block created");
        vtxid.clear();
        mempool.queryHashes(vtxid);
        MinTxns.clear();
        MinTxns.push_back(*mempool.get(vtxid.at(0)));
        tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();
        CreateBlock(MinTxns, scriptPubKey);
        zerocoinState->usedCoinSerials = tempSerials;

        mempool.clear();
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed");
        //This test confirms that a block containing a double spend is rejected and not added in the chain
        BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Double spend - Block added to chain even though same spend in previous block");

        vtxid.clear();
        MinTxns.clear();
        mempool.clear();
        zerocoinState->mempoolCoinSerials.clear();

        // Test: send to third party address.
        // mint two of each denom
        denominationPairs.clear();
        for(int i=0;i<2;i++){
             std::pair<std::string, int> denominationPair(denominationsForTx[i], 2);
             denominationPairs.push_back(denominationPair);
        }
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");

        // verify mints got to mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mint tx not added to mempool");

        // add block
        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        wtx.Init(NULL);
        //Add 5 more blocks
        for (int i = 0; i < 5; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKey);
            wtx.Init(NULL);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
        previousHeight = chainActive.Height();

        // send to third party address.
        thirdPartyAddress = "TXYb6pEWBDcxQvTxbFQ9sEV1c3rWUPGW3v";
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
        BOOST_CHECK_MESSAGE(wtx.vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.vout.size() == 1, "Incorrect output size");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "third party spend not added to mempool");

        b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        wtx.Init(NULL);

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "third party spend not succeeded");

        vtxid.clear();
        MinTxns.clear();
        mempool.clear();
        zerocoinState->Reset();
    }

    thirdPartyAddress = "";

    // create transactions using the same denomination
    for(int i = 0; i < 5; i++)
    {
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        denominationsForTx.push_back(denominations[i]);
        string stringError;
        printf("Testing denominations %s and %s\n", denominationsForTx[0].c_str(), denominationsForTx[1].c_str());
        denominationPairs.clear();
        std::pair<std::string, int> denominationPair(denominations[i].c_str(), 2);
        denominationPairs.push_back(denominationPair);

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Same denom mint tx not added to mempool");

        // add block
        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        wtx.Init(NULL);
        //Add 5 more blocks
        for (int i = 0; i < 5; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKey);
            wtx.Init(NULL);
        }
        // printf("%d\n", chainActive.Height());
        BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
        previousHeight = chainActive.Height();

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
        BOOST_CHECK_MESSAGE(wtx.vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.vout.size() == 1, "Incorrect output size");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Same denom spend not added to mempool");

        b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        wtx.Init(NULL);

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Same denom spend not succeeded");

        vtxid.clear();
        MinTxns.clear();
        mempool.clear();
        zerocoinState->Reset();
    }
}

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_usedinput){
    vector<string> denominationsForTx;
    vector<pair<std::string, int>> denominationPairs;
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    std::vector<std::string> denominations = {"0.1", "0.5", "1", "10", "100"};

    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();

    pwalletMain->SetBroadcastTransactions(true);

    // attempt to add a mixed input spend in one block, and use of the inputs into another tx in the next block.
    denominationsForTx.clear();
    denominationsForTx.push_back(denominations[rand() % 5]);
    denominationsForTx.push_back(denominations[rand() % 5]);
    printf("Testing denominations %s and %s\n", denominationsForTx[0].c_str(), denominationsForTx[1].c_str());
    string stringError;

    denominationPairs.clear();
    for (int i = 0; i < 2; i++){
        std::pair<std::string, int> denominationPair(denominationsForTx[i].c_str(), 2);
        denominationPairs.push_back(denominationPair);
    }

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Used input mint not added to mempool");

    // add block
    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock(MinTxns, scriptPubKey);
    wtx.Init(NULL);
    //Add 5 more blocks
    for (int i = 0; i < 5; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        b = CreateAndProcessBlock(noTxns, scriptPubKey);
        wtx.Init(NULL);
    }
    // printf("%d\n", chainActive.Height());
    BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
    previousHeight = chainActive.Height();

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
    BOOST_CHECK_MESSAGE(wtx.vin.size() == denominationsForTx.size(), "Incorrect inputs size");
    BOOST_CHECK_MESSAGE(wtx.vout.size() == 1, "Incorrect output size");

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
    BOOST_CHECK_MESSAGE(wtx.vin.size() == denominationsForTx.size(), "Incorrect inputs size");
    BOOST_CHECK_MESSAGE(wtx.vout.size() == 1, "Incorrect output size");

    BOOST_CHECK_MESSAGE(mempool.size() == 2, "Same denom spend not added to mempool");

    b = CreateAndProcessBlock(MinTxns, scriptPubKey);
    wtx.Init(NULL);

    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Same denom spend not succeeded");

    // Now add one of the inputs into another spend and verify it fails..
    denominationsForTx.pop_back();
    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "First spend succeeded with used mint");
    BOOST_CHECK_MESSAGE(stringError=="it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", "Incorrect error message: " + stringError);

    // Now mint two more of the first denomination, but don't mine the needed blocks, preventing their usage. verify transaction creation fails
    denominationPairs.clear();
    std::pair<std::string, int> denominationPair(denominationsForTx[0], 2);
    denominationPairs.push_back(denominationPair);
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");

    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Second spend succeeded with used mint");
    BOOST_CHECK_MESSAGE(stringError=="it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", "Incorrect error message: " + stringError);

    vtxid.clear();
    MinTxns.clear();
    mempool.clear();
    zerocoinState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()