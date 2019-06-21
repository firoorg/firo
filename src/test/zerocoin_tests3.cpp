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

BOOST_FIXTURE_TEST_SUITE(zerocoin_tests3, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(zerocoin_mintspend)
{
    string denomination;
    vector<uint256> vtxid;
    std::vector<string> denominations = {"1", "10", "25", "50", "100"};
    for(int i = 0; i < 5; i++)
    {
        denomination = denominations[i];
        printf("Testing denomination %s\n", denomination.c_str());
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);

        //Verify Mint is successful
        //DZC BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str()), stringError + " - Create Mint failed");
        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str()), stringError + " - Create Mint not failed");

        //Verify Mint gets in the mempool
        //DZC BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mint was added to mempool");
        return;

        int previousHeight = chainActive.Height();
        CBlock b = CreateAndProcessBlock({}, scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination, false, true), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "No zerocoin mints to spend, spending sigma mints disabled. At least 2 mints with at least 6 confirmations are required to spend a coin.", stringError + " - Incorrect error message");

            CBlock b = CreateAndProcessBlock({}, scriptPubKey);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination, false, true), "Spend succeeded although not at least two mints");
        BOOST_CHECK_MESSAGE(stringError == "No zerocoin mints to spend, spending sigma mints disabled. At least 2 mints with at least 6 confirmations are required to spend a coin.", stringError + " - Incorrect error message");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str()), stringError + "Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock({}, scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");


        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination, false, true), "Spend succeeded although not confirmed by 6 blocks");
            BOOST_CHECK_MESSAGE(stringError == "No zerocoin mints to spend, spending sigma mints disabled. At least 2 mints with at least 6 confirmations are required to spend a coin.", stringError + " - Incorrect error message");
            CBlock b = CreateAndProcessBlock({}, scriptPubKey);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination, false, true), "Spend failed");

        // Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");
        vtxid.clear();

        b = CreateBlock({}, scriptPubKey);
        previousHeight = chainActive.Height();
        mempool.clear();
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        //Delete usedCoinSerials since we deleted the mempool
        CZerocoinState *zerocoinStatex = CZerocoinState::GetZerocoinState();
        zerocoinStatex->usedCoinSerials.clear();
        zerocoinStatex->mempoolCoinSerials.clear();

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination, true, true), "Spend created although double");
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
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str()), stringError + "Create Mint failed");

        b = CreateAndProcessBlock({}, scriptPubKey);

        vtxid.clear();
        mempool.clear();
    }
}

BOOST_AUTO_TEST_SUITE_END()
