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
#include "main.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "zerocoin.h"

#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

extern CCriticalSection cs_main;
using namespace std;

CScript scriptPubKey;

bool no_check( std::runtime_error const& ex ) { return true; }

struct ZerocoinTestingSetup : public TestingSetup {
    ZerocoinTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {
        CPubKey newKey;
        BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

        string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        //Mine 200 blocks so that we have funds for creating mints and we are over these limits:
        //mBlockHeightConstants["ZC_V1_5_STARTING_BLOCK"] = 150;
        //mBlockHeightConstants["ZC_CHECK_BUG_FIXED_AT_BLOCK"] = 140;

        printf("Balance before %ld\n", pwalletMain->GetBalance());
        scriptPubKey = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        for (int i = 0; i < 200; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
            coinbaseTxns.push_back(b.vtx[0]);
            LOCK(cs_main);
            {
                LOCK(pwalletMain->cs_wallet);
                pwalletMain->AddToWalletIfInvolvingMe(b.vtx[0], &b, true);
            }
        }

        printf("Balance after 200 blocks: %ld\n", pwalletMain->GetBalance());
    }

    CBlock CreateBlock(const std::vector<CMutableTransaction>& txns,
                       const CScript& scriptPubKey) {
        const CChainParams& chainparams = Params();
        CBlockTemplate *pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        CBlock& block = pblocktemplate->block;

        // Replace mempool-selected txns with just coinbase plus passed-in txns:
        if(txns.size() > 0) {
            block.vtx.resize(1);
            BOOST_FOREACH(const CMutableTransaction& tx, txns)
                block.vtx.push_back(tx);
        }
        // IncrementExtraNonce creates a valid coinbase and merkleRoot
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

        while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())){
            ++block.nNonce;
        }

        //delete pblocktemplate;
        return block;
    }

    bool ProcessBlock(CBlock &block) {
        const CChainParams& chainparams = Params();
        CValidationState state;
        return ProcessNewBlock(state, chainparams, NULL, &block, true, NULL, false);
    }

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
                                 const CScript& scriptPubKey){

        CBlock block = CreateBlock(txns, scriptPubKey);
        BOOST_CHECK_MESSAGE(ProcessBlock(block), "Processing block failed");
        return block;
    }

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

BOOST_FIXTURE_TEST_SUITE(zerocoin_tests, ZerocoinTestingSetup)

BOOST_AUTO_TEST_CASE(zerocoin_mintspend)
{
    string denomination;
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
    std::vector<std::string> denominations = {"1", "10", "25", "50", "100"};
    for(int i = 0; i < 5; i++)
    {
        denomination = denominations[i];
        printf("Testing denomination %s\n", denomination.c_str());
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);

        //Verify Mint is successful
        vector<pair<int,int>> denominationPairs;
        std::pair<int,int> denominationPair(stoi(denomination), 1);
        denominationPairs.push_back(denominationPair);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

        //Verify Mint gets in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        int previousHeight = chainActive.Height();
        CBlock b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");

            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend succeeded although not at least two mints");
        BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");


        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + "Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        MinTxns.clear();

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");


        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        //Create two spend transactions using the same mint.
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend failed");
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), true), stringError + " - Spend failed");

        //Try to put two in the same block and it will fail, expect 1
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends was not added to mempool");

        //NOT POSSIBLE - Hacky method of forcing double spends to be added to same block
        // vtxid.clear();
        // mempool.queryHashes(vtxid);
        // MinTxns.clear();
        // MinTxns.push_back(*mempool.get(vtxid.at(0)));
        // MinTxns.push_back(*mempool.get(vtxid.at(1)));
        // b = CreateBlock(MinTxns, scriptPubKey);
        // //Reset zerocoinTxInfo to perform check again as if we received the block from another node
        // b.zerocoinTxInfo = std::make_shared<CZerocoinTxInfo>();
        // previousHeight = chainActive.Height();
        // BOOST_CHECK_MESSAGE(!ProcessBlock(b), "ProcessBlock succeeded and should have failed on double spend");
        // BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Double spend - Block added to chain even though two same spends in same block");
        // mempool.clear();
        // //Create a new spend transaction from a mint that wallet think is used
        // BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), true), "Spend failed");

        //Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        vtxid.clear();
        MinTxns.clear();

        b = CreateBlock(MinTxns, scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), stringError + " - Spend failed");

        //Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        MinTxns.clear();

        b = CreateBlock(MinTxns, scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        //Test double spend with previous spend in last block
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), true), "Spend created although double");
        //This confirms that double spend is blocked and cannot enter mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not empty although mempool should reject double spend");

        //Temporary disable usedCoinSerials check to force double spend in mempool
        CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
        auto tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), true), "Spend created although double");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not set");
        zerocoinState->usedCoinSerials = tempSerials;

        MinTxns.clear();
        BOOST_CHECK_EXCEPTION(CreateBlock(MinTxns, scriptPubKey), std::runtime_error, no_check);
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not set");
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
    }
}

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_many)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    std::vector<std::string> denominations = {"1", "10", "25", "50", "100"};

    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

    pwalletMain->SetBroadcastTransactions(true);

    vector<pair<int,int>> denominationPairs;

    for(int i = 0; i < 4; i++)
    {
        thirdPartyAddress = "";
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        denominationsForTx.push_back(denominations[i+1]); 
        printf("Testing denominations %s and %s\n", denominationsForTx[0].c_str(), denominationsForTx[1].c_str());
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);
        denominationPairs.clear();
        //Verify Mint is successful
        for(int i=0;i<2;i++){
             std::pair<int,int> denominationPair(stoi(denominationsForTx[i]), 1);
             denominationPairs.push_back(denominationPair);
        }
                
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

        //Verify mint tx get added in the mempool
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
        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded although not at least two mints");
        BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + "Create Mint failed");
        //BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationsForTx[1].c_str()), stringError + "Create Mint failed");

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

        //Create two spend transactions using the same mints
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend failed");
        BOOST_CHECK_MESSAGE(wtx.vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.vout.size() == 1, "Incorrect output size");
        wtx.Init(NULL);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx, true), stringError + " - Spend failed");

        //Try to put two in the same block and it will fail, expect 1
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
             std::pair<int,int> denominationPair(stoi(denominationsForTx[i]), 2);
             denominationPairs.push_back(denominationPair);
        }
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

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
        // printf("%d\n", chainActive.Height());
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
        printf("Testing denominations %s and %s\n", denominationsForTx[0].c_str(), denominationsForTx[1].c_str());
        denominationPairs.clear();
        std::pair<int,int> denominationPair(stoi(denominations[i].c_str()), 2);
        denominationPairs.push_back(denominationPair);

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

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
        zerocoinState->mempoolCoinSerials.clear();
    }
}

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_usedinput){
    vector<string> denominationsForTx;
    vector<pair<int,int>> denominationPairs;
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
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
    printf("Testing denominations %s and %s\n", denominationsForTx[0].c_str(), denominationsForTx[1].c_str());
    string stringError;

    for (int i = 0; i < 2; i++){
        std::pair<int,int> denominationPair(stoi(denominationsForTx[i].c_str()), 2);
        denominationPairs.push_back(denominationPair);
    }

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

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
    std::pair<int,int> denominationPair(stoi(denominationsForTx[0]), 2);
    denominationPairs.push_back(denominationPair);
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Second spend succeeded with used mint");
    BOOST_CHECK_MESSAGE(stringError=="it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", "Incorrect error message: " + stringError);

    vtxid.clear();
    MinTxns.clear();
    mempool.clear();
    zerocoinState->mempoolCoinSerials.clear();
}

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_numinputs){
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
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
    printf("Testing number of inputs for denomination %s", denominations[denominationIndexA].c_str());
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

    // Check that the tx creation fails.
    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded even though number of inputs > ZC_SPEND_LIMIT");

    // Next add 3 transactions with 2 inputs each, verify mempool==3. mine a block. Verify mempool still has 1 tx.
    for(int i=0;i<3;i++){
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[denominationIndexA]);
        denominationsForTx.push_back(denominations[denominationIndexB]);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend Failed");
    }

    BOOST_CHECK_MESSAGE(mempool.size() == 3, "Num input spends not added to mempool");

    // add block
    b = CreateAndProcessBlock(MinTxns, scriptPubKey);
    wtx.Init(NULL);

    BOOST_CHECK_MESSAGE(mempool.size() != 3 && mempool.size() == 1 && mempool.size() != 0, "Mempool not correctly cleared: Block spend limit not enforced.");

    vtxid.clear();
    MinTxns.clear();
    mempool.clear();
    zerocoinState->mempoolCoinSerials.clear();
}
BOOST_AUTO_TEST_SUITE_END()

