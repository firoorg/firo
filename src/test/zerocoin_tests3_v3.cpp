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
#include "sigma.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(zerocoin_tests3_v3, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_v3)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    string denomination;
    std::vector<string> denominations = {"0.1", "0.5", "1", "10", "100"};

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    for(int i = 0; i < 5; i++)
    {
        denomination = denominations[i];
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);

        //Verify Mint is successful
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str(), SIGMA), stringError + " - Create Mint failed");

        //Verify Mint gets in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        int previousHeight = chainActive.Height();
        CBlock b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");

            CBlock b = CreateAndProcessBlock(scriptPubKey);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend succeeded although not at least two mints");
        BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str(), SIGMA), stringError + "Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");


        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "it has to have at least two mint coins with at least 6 confirmation in order to spend a coin", stringError + " - Incorrect error message");
            CBlock b = CreateAndProcessBlock(scriptPubKey);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend failed");

        // Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        b = CreateBlock(scriptPubKey);
        previousHeight = chainActive.Height();
        mempool.clear();
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        // Delete usedCoinSerials since we deleted the mempool
        sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
        sigmaState->containers.usedCoinSerials.clear();
        sigmaState->mempoolCoinSerials.clear();

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str(), true), "Spend created although double");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool did not receive the transaction");

        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        //Since new block contained a TX with the same serial as the TX in mempool, confirm that mempool is cleared
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        //Confirm that on disconnect block transaction is returned to mempool
        DisconnectBlocks(1);

        LOCK(cs_main);
        {
            CValidationState state;
            const CChainParams& chainparams = Params();
            InvalidateBlock(state, chainparams, mapBlockIndex[b.GetHash()]);
        }

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool should get the transaction of disconnected block");

        //This mint is just to create a block with the new hash
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str(), SIGMA), stringError + "Create Mint failed");

        b = CreateAndProcessBlock(scriptPubKey);
        mempool.clear();

    }
    sigmaState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
