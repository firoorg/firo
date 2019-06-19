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

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(hdmint_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(deterministic)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    int mintCount = 0;

    std::vector<std::string> denominations = {"0.05", "0.1", "0.5", "1", "10", "25", "100"};

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    pwalletMain->SetBroadcastTransactions(true);

    vector<pair<std::string, int>> denominationPairs;

    vector<CHDMint> vDMints;
    vector<CHDMint> vDMintsRegenerated;
    vector<CHDMint> vDMintsBuilder;

    for(int i = 0; i < denominations.size() - 1; i++)
    {
        vDMintsBuilder.clear();
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
             mintCount++;
        }

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, vDMintsBuilder, SIGMA), stringError + " - Create Mint failed");

        // Verify mint tx get added in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");

        // Verify correct mint count
        BOOST_CHECK(mintCount == zwalletMain->GetCount());

        for(auto& mint : vDMintsBuilder){
            vDMints.push_back(mint);
        }

            b = CreateBlock({}, scriptPubKey);
            int previousHeight = chainActive.Height();
            BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
            BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    }

    // We now have 10 mints, each stored in vDMints. reset the count and regenerate
    zwalletMain->SetCount(0);
    mintCount = 0;

    for(int i = 0; i < denominations.size() - 1; i++)
    {
        vDMintsBuilder.clear();
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
             mintCount++;
        }

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, vDMintsBuilder, SIGMA), stringError + " - Create Mint failed");

        // Verify mint tx get added in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");

        // Verify correct mint count
        BOOST_CHECK(mintCount == zwalletMain->GetCount());

        for(auto& mint : vDMintsBuilder){
            vDMintsRegenerated.push_back(mint);
        }

        b = CreateBlock({}, scriptPubKey);
        int previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

    }

    BOOST_CHECK(vDMints.size() == vDMintsRegenerated.size());

    for(int i=0; i<vDMints.size();i++){
        BOOST_CHECK(vDMints[i].GetCount() == vDMintsRegenerated[i].GetCount());
        BOOST_CHECK(vDMints[i].GetSeedId() == vDMintsRegenerated[i].GetSeedId());
        BOOST_CHECK(vDMints[i].GetSerialHash() == vDMintsRegenerated[i].GetSerialHash());
        BOOST_CHECK(vDMints[i].GetPubCoinHash() == vDMintsRegenerated[i].GetPubCoinHash());
    }

}

BOOST_AUTO_TEST_SUITE_END()
