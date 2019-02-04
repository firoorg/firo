
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
#include "zerocoin_v3.h"

#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

extern CCriticalSection cs_main;
using namespace std;

CScript scriptPubKey2_v3;

bool no_check2_v3( std::runtime_error const& ex ) { return true; }

struct ZerocoinTestingSetup2 : public TestingSetup {
    ZerocoinTestingSetup2() : TestingSetup(CBaseChainParams::REGTEST)
    {
        CPubKey newKey;
        BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

        string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        printf("Balance before %ld\n", pwalletMain->GetBalance());
        scriptPubKey2_v3 = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        for (int i = 0; i < 109; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey2_v3);
            coinbaseTxns.push_back(b.vtx[0]);
            LOCK(cs_main);
            {
                LOCK(pwalletMain->cs_wallet);
                pwalletMain->AddToWalletIfInvolvingMe(b.vtx[0], &b, true);
            }
        }

        printf("Balance after 109 blocks: %ld\n", pwalletMain->GetBalance());
    }

    CBlock CreateBlock(const std::vector<CMutableTransaction>& txns,
                       const CScript& scriptPubKey2_v3) {
        const CChainParams& chainparams = Params();
        CBlockTemplate *pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey2_v3);
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
    // scriptPubKey2_v3, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
                                 const CScript& scriptPubKey2_v3){

        CBlock block = CreateBlock(txns, scriptPubKey2_v3);
        BOOST_CHECK_MESSAGE(ProcessBlock(block), "Processing block failed");
        return block;
    }

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

BOOST_FIXTURE_TEST_SUITE(zerocoin_tests2_v3, ZerocoinTestingSetup2)

BOOST_AUTO_TEST_CASE(zerocoin_mintspend2_v3)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
    //109 blocks already minted

    std::vector<string> denominations = {"0.1", "0.5", "1"};
    for(string denomination : denominations) {
        printf("Testing denomination %s\n", denomination.c_str());
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);

        printf("Creating 5 mints at height %d\n", chainActive.Height() + 1);
        //Block 110 create 5 mints
        //Verify Mint is successful
        for(int i = 0; i < 5; i++)
        {
            BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str(), SIGMA), stringError + " - Create Mint failed");
        }

        //Put 5 in the same block
        BOOST_CHECK_MESSAGE(mempool.size() == 5, "Mints were not added to mempool");

        vtxid.clear();
        mempool.queryHashes(vtxid);
        MinTxns.clear();
        for(int i = 0; i < 5; i++)
            MinTxns.push_back(*mempool.get(vtxid.at(i)));

        int previousHeight = chainActive.Height();
        CBlock b = CreateAndProcessBlock(MinTxns, scriptPubKey2_v3);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        printf("Creating 6 mints at height %d\n", chainActive.Height() + 1);
        //Block 111, put 6 mints
        for(int i = 0; i < 6; i++)
            BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str(), SIGMA), stringError + " - Create Mint failed");

        //Put 6 in the same block
        BOOST_CHECK_MESSAGE(mempool.size() == 6, "Mints were not added to mempool");

        vtxid.clear();
        mempool.queryHashes(vtxid);
        MinTxns.clear();
        for(int i = 0; i < 6; i++)
            MinTxns.push_back(*mempool.get(vtxid.at(i)));

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(MinTxns, scriptPubKey2_v3);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        for (int i = 0; i < 5; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey2_v3);
        }

        printf("Creating 10 mints and one spend at height %d\n", chainActive.Height() + 1);
        //Block 117, put 10 mints and one spend
        for(int i = 0; i < 10; i++)
            BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str(), SIGMA), stringError + " - Create Mint failed");
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend failed");

        //Put 11 in the same block
        BOOST_CHECK_MESSAGE(mempool.size() == 11, "Mints were not added to mempool");

        vtxid.clear();
        mempool.queryHashes(vtxid);
        MinTxns.clear();
        for(int i = 0; i < 11; i++)
            MinTxns.push_back(*mempool.get(vtxid.at(i)));

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(MinTxns, scriptPubKey2_v3);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        printf("Creating 20 blocks with 1 spend each starting at height %d\n", chainActive.Height() + 1);
        //20 spends in 20 blocks
        for(int i = 0; i < 20; i++) {

            BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend failed");
            BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends were not added to mempool");
            vtxid.clear();
            mempool.queryHashes(vtxid);
            MinTxns.clear();
            MinTxns.push_back(*mempool.get(vtxid.at(0)));
            previousHeight = chainActive.Height();
            b = CreateAndProcessBlock(MinTxns, scriptPubKey2_v3);
            BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
            BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
        }

        printf("Creating 19 mints at height %d\n", chainActive.Height() + 1);
        //Put 19 mints
        for(int i = 0; i < 19; i++)
            BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str(), SIGMA), stringError + " - Create Mint failed");

        //Put 19 in the same block
        BOOST_CHECK_MESSAGE(mempool.size() == 19, "Mints were not added to mempool");

        vtxid.clear();
        mempool.queryHashes(vtxid);
        MinTxns.clear();
        for(int i = 0; i < 19; i++)
            MinTxns.push_back(*mempool.get(vtxid.at(i)));

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(MinTxns, scriptPubKey2_v3);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        for (int i = 0; i < 5; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey2_v3);
        }

        printf("Creating 19 blocks with 1 spend each starting at height %d\n", chainActive.Height() + 1);
        //19 spends in 19 blocks
        for(int i = 0; i < 19; i++) {
            BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", denomination.c_str()), "Spend failed");
            BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends were not added to mempool");
            vtxid.clear();
            mempool.queryHashes(vtxid);
            MinTxns.clear();
            MinTxns.push_back(*mempool.get(vtxid.at(0)));
            previousHeight = chainActive.Height();
            b = CreateAndProcessBlock(MinTxns, scriptPubKey2_v3);
            BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
            BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
        }
    }

    vtxid.clear();
    MinTxns.clear();
    mempool.clear();
    zerocoinState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
