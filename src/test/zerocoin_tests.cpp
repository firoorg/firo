//In late April 2019 the Zerocoin functionality has been disabled.
//The tests are changed so to verify it is disabled but change as little functionality as possible
//The initial functionality is left in here after comment //DZC
#include "util.h"

#include "clientversion.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "test/test_bitcoin.h"

#include <stdint.h>
#include <vector>
#include <iostream>

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "zerocoin.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(zerocoin_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(zerocoin_mintspend)
{
    FakeTestnet fakeTestnet;

    string denomination;
    vector<uint256> vtxid;
    std::vector<std::string> denominations = {"1", "10", "25", "50", "100"};
    for(int i = 0; i < 5; i++)
    {
        denomination = denominations[i];
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);

        //Verify Mint is successful
        vector<pair<std::string, int>> denominationPairs;
        std::pair<std::string, int> denominationPair(denomination, 1);
        denominationPairs.push_back(denominationPair);
        //DZC BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");
        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint not failed");

        //Verify Mint gets in the mempool
        //DZC BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mint was added to mempool");
        return;

        int previousHeight = chainActive.Height();
        CBlock b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), false, true), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "No zerocoin mints to spend, spending sigma mints disabled. At least 2 mints with at least 6 confirmations are required to spend a coin.", stringError + " - Incorrect error message");

            CBlock b = CreateAndProcessBlock(scriptPubKey);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), false, true), "Spend succeeded although not at least two mints");
        BOOST_CHECK_MESSAGE(stringError == "No zerocoin mints to spend, spending sigma mints disabled. At least 2 mints with at least 6 confirmations are required to spend a coin.", stringError + " - Incorrect error message");


        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + "Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");


        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), false, true), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "No zerocoin mints to spend, spending sigma mints disabled. At least 2 mints with at least 6 confirmations are required to spend a coin.", stringError + " - Incorrect error message");
            CBlock b = CreateAndProcessBlock(scriptPubKey);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        //Create two spend transactions using the same mint.
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), false, true), "Spend failed");
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), true, true), stringError + " - Spend failed");

        //Try to put two in the same block and it will fail, expect 1
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends was not added to mempool");

       //Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        vtxid.clear();
        b = CreateBlock(scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), false, true), stringError + " - Spend failed");

        //Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        b = CreateBlock(scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        //Test double spend with previous spend in last block
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), true, true), "Spend created although double");
        //This confirms that double spend is blocked and cannot enter mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not empty although mempool should reject double spend");

        //Temporary disable usedCoinSerials check to force double spend in mempool
        CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
        auto tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), true, true), "Spend created although double");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not set");
        zerocoinState->usedCoinSerials = tempSerials;

        BOOST_CHECK_EXCEPTION(CreateBlock(scriptPubKey), std::runtime_error, no_check);
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not set");
        tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();
        CreateBlock(scriptPubKey);
        zerocoinState->usedCoinSerials = tempSerials;

        mempool.clear();
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed");
        //This test confirms that a block containing a double spend is rejected and not added in the chain
        BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Double spend - Block added to chain even though same spend in previous block");

        mempool.clear();
    }
}

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_many)
{
    FakeTestnet FakeTestnet;

    vector<string> denominationsForTx;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    std::vector<std::string> denominations = {"1", "10", "25", "50", "100"};

    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

    pwalletMain->SetBroadcastTransactions(true);

    vector<pair<std::string, int>> denominationPairs;

    for(int i = 0; i < 4; i++)
    {
        thirdPartyAddress = "";
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        denominationsForTx.push_back(denominations[i+1]); 
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);
        denominationPairs.clear();
        //Verify Mint is successful
        for(int i = 0; i < 2; ++i) {
             std::pair<std::string, int> denominationPair(denominationsForTx[i], 1);
             denominationPairs.push_back(denominationPair);
        }

        //DZC BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");
        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint not failed");

        //Verify mint tx get added in the mempool
        //DZC BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mint tx was added to mempool");
        return;

        int previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        previousHeight = chainActive.Height();
        wtx.Init(NULL);
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");

            b = CreateAndProcessBlock(scriptPubKey);
            wtx.Init(NULL);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        wtx.Init(NULL);
        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded although not at least two mints");
        BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + "Create Mint failed");
        //BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationsForTx[1].c_str()), stringError + "Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");


        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        wtx.Init(NULL);
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");
            b = CreateAndProcessBlock(scriptPubKey);
            wtx.Init(NULL);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        //Create two spend transactions using the same mints
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
        BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");
        wtx.Init(NULL);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx, true), stringError + " - Spend failed");

        //Try to put two in the same block and it will fail, expect 1
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends was not added to mempool");

        b = CreateBlock(scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), stringError + " - Spend failed");
        BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

        //Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        b = CreateBlock(scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
        wtx.Init(NULL);
        //Test double spend with previous spend in last block
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx, true), "Spend created although double");
        //This confirms that double spend is blocked and cannot enter mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not empty although mempool should reject double spend");

        //Temporary disable usedCoinSerials check to force double spend in mempool
        auto tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();

        wtx.Init(NULL);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx, true), "Spend created although double");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mempool not set after used coin serials removed");
        zerocoinState->usedCoinSerials = tempSerials;

        BOOST_CHECK_EXCEPTION(CreateBlock(scriptPubKey), std::runtime_error, no_check);
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mempool not set after block created");
        tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();
        CreateBlock(scriptPubKey);
        zerocoinState->usedCoinSerials = tempSerials;

        mempool.clear();
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed");
        //This test confirms that a block containing a double spend is rejected and not added in the chain
        BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Double spend - Block added to chain even though same spend in previous block");

        mempool.clear();
        zerocoinState->mempoolCoinSerials.clear();

        // Test: send to third party address.
        // mint two of each denom
        denominationPairs.clear();
        for(int i=0;i<2;i++){
             std::pair<std::string, int> denominationPair(denominationsForTx[i], 2);
             denominationPairs.push_back(denominationPair);
        }
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

        // verify mints got to mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mint tx not added to mempool");

        // add block
        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);
        //Add 5 more blocks
        for (int i = 0; i < 5; i++)
        {
            b = CreateAndProcessBlock(scriptPubKey);
            wtx.Init(NULL);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
        previousHeight = chainActive.Height();

        // send to third party address.
        thirdPartyAddress = "TXYb6pEWBDcxQvTxbFQ9sEV1c3rWUPGW3v";
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
        BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "third party spend not added to mempool");

        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "third party spend not succeeded");

        mempool.clear();
        zerocoinState->mempoolCoinSerials.clear();
    }

    thirdPartyAddress = "";

    // create transactions using the same denomination
    for(int i = 0; i < 5; i++)
    {
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        denominationsForTx.push_back(denominations[i]); 
        string stringError;
        denominationPairs.clear();
        std::pair<std::string, int> denominationPair(denominations[i].c_str(), 2);
        denominationPairs.push_back(denominationPair);

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Same denom mint tx not added to mempool");

        // add block
        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);
        //Add 5 more blocks
        for (int i = 0; i < 5; i++)
        {
            b = CreateAndProcessBlock(scriptPubKey);
            wtx.Init(NULL);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
        previousHeight = chainActive.Height();

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
        BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Same denom spend not added to mempool");

        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Same denom spend not succeeded");

        mempool.clear();
        zerocoinState->mempoolCoinSerials.clear();
    }
}

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_usedinput){

    return;
    
    vector<string> denominationsForTx;
    vector<pair<std::string, int>> denominationPairs;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    std::vector<std::string> denominations = {"1", "10", "25", "50", "100"};

    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

    pwalletMain->SetBroadcastTransactions(true);

    // attempt to add a mixed input spend in one block, and use of the inputs into another tx in the next block.
    denominationsForTx.clear();
    denominationsForTx.push_back(denominations[rand() % 5]);
    denominationsForTx.push_back(denominations[rand() % 5]); 
    string stringError;

    denominationPairs.clear();
    for (int i = 0; i < 2; i++){
        std::pair<std::string, int> denominationPair(denominationsForTx[i].c_str(), 2);
        denominationPairs.push_back(denominationPair);
    }

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Used input mint not added to mempool");

    // add block
    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock(scriptPubKey);
    wtx.Init(NULL);
    //Add 5 more blocks
    for (int i = 0; i < 5; i++)
    {
        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);
    }
    BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
    previousHeight = chainActive.Height();

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
    BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == denominationsForTx.size(), "Incorrect inputs size");
    BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
    BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == denominationsForTx.size(), "Incorrect inputs size");
    BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

    BOOST_CHECK_MESSAGE(mempool.size() == 2, "Same denom spend not added to mempool");

    b = CreateAndProcessBlock(scriptPubKey);
    wtx.Init(NULL);

    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Same denom spend not succeeded");

    // Now add one of the inputs into another spend and verify it fails..
    denominationsForTx.pop_back();
    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "First spend succeeded with used mint");
    BOOST_CHECK_MESSAGE(stringError=="it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", "Incorrect error message: " + stringError);

    // Now mint two more of the first denomination, but don't mine the needed blocks, preventing their usage. verify transaction creation fails
    denominationPairs.clear();
    std::pair<std::string, int> denominationPair(denominationsForTx[0], 2);
    denominationPairs.push_back(denominationPair);
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Second spend succeeded with used mint");
    BOOST_CHECK_MESSAGE(stringError=="it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", "Incorrect error message: " + stringError);

    mempool.clear();
    zerocoinState->mempoolCoinSerials.clear();
}

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_numinputs){
    return;
    
    vector<string> denominationsForTx;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;
    string stringError;

    std::vector<std::string> denominations = {"1", "10", "25", "50", "100"};
    int denominationIndexA = rand() % 5;
    int denominationIndexB = (denominationIndexA + 5) %4; //guarantees a different number in the range

    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

    pwalletMain->SetBroadcastTransactions(true);

    // attempt to create a zerocoin spend with more than ZC_SPEND_LIMIT inputs.
    denominationsForTx.clear();

    for (int i = 0; i < (ZC_SPEND_LIMIT+1)*2; i++){
        denominationsForTx.push_back(denominations[denominationIndexA]);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominations[denominationIndexA].c_str()), stringError + " - Create Mint failed");
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominations[denominationIndexB].c_str()), stringError + " - Create Mint failed");
        if(i<=ZC_SPEND_LIMIT){
            denominationsForTx.push_back(denominations[denominationIndexA]);
        }
    }
    
    BOOST_CHECK_MESSAGE(mempool.size() == (ZC_SPEND_LIMIT+1)*4, "Num input mints not added to mempool");

    // add block
    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock(scriptPubKey);
    wtx.Init(NULL);
    //Add 5 more blocks
    for (int i = 0; i < 5; i++)
    {
        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);
    }

    BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
    previousHeight = chainActive.Height();

    // Check that the tx creation fails.
    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded even though number of inputs > ZC_SPEND_LIMIT");

    // Next add 3 transactions with 2 inputs each, verify mempool==3. mine a block. Verify mempool still has 1 tx.
    for(int i=0;i<3;i++){
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[denominationIndexA]);
        denominationsForTx.push_back(denominations[denominationIndexB]);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend Failed");
    }

    BOOST_CHECK_MESSAGE(mempool.size() == 3, "Num input spends not added to mempool");

    // add block
    b = CreateAndProcessBlock(scriptPubKey);
    wtx.Init(NULL);

    BOOST_CHECK_MESSAGE(mempool.size() != 3 && mempool.size() == 1 && mempool.size() != 0, "Mempool not correctly cleared: Block spend limit not enforced.");

    mempool.clear();
    zerocoinState->mempoolCoinSerials.clear();
}
BOOST_AUTO_TEST_SUITE_END()

