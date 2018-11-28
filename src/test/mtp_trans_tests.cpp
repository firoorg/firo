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

#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

extern CCriticalSection cs_main;
using namespace std;

CScript scriptPubKeyMtp;

bool mtp_no_check( std::runtime_error const& ex ) { return true; }

struct MtpTransTestingSetup : public TestingSetup {
    MtpTransTestingSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        CPubKey newKey;
        BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

        string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        printf("Balance before %ld\n", pwalletMain->GetBalance());
        scriptPubKeyMtp = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        bool mtp = false;
        CBlock b;
        //Create 150 height chain
        for (int i = 0; i < 150; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKeyMtp, mtp);
            coinbaseTxns.push_back(b.vtx[0]);
            LOCK(cs_main);
            {
                LOCK(pwalletMain->cs_wallet);
                pwalletMain->AddToWalletIfInvolvingMe(b.vtx[0], &b, true);
            }
        }


        printf("Balance after 150 blocks: %ld\n", pwalletMain->GetBalance());
    }

    CBlock CreateBlock(const std::vector<CMutableTransaction>& txns,
                       const CScript& scriptPubKeyMtp, bool mtp = false) {
        const CChainParams& chainparams = Params();
        CBlockTemplate *pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKeyMtp);
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
        if(mtp) {
            while (!CheckMerkleTreeProof(block, chainparams.GetConsensus())){
                block.mtpHashValue = mtp::hash(block, Params().GetConsensus().powLimit);
            }
        }
        else {
            while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())){
                ++block.nNonce;
            }
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
    // scriptPubKeyMtp, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
                                 const CScript& scriptPubKeyMtp, bool mtp = false){

        CBlock block = CreateBlock(txns, scriptPubKeyMtp, mtp);
        BOOST_CHECK_MESSAGE(ProcessBlock(block), "Processing block failed");
        return block;
    }

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

BOOST_FIXTURE_TEST_SUITE(mtp_trans_tests, MtpTransTestingSetup)

BOOST_AUTO_TEST_CASE(mtp_transition)
{
    bool mtp = false;
    CBlock b;

    //Transition to MTP
    mtp = true;
    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(GetAdjustedTime());

    int previousHeight = chainActive.Height();
    std::vector<CMutableTransaction> noTxns;
    b = CreateAndProcessBlock(noTxns, scriptPubKeyMtp, mtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height() - 1, "Block not connected");
    coinbaseTxns.push_back(b.vtx[0]);
    LOCK(cs_main);
    {
        LOCK(pwalletMain->cs_wallet);
        pwalletMain->AddToWalletIfInvolvingMe(b.vtx[0], &b, true);
    }

    previousHeight = chainActive.Height();
    //Disconnect MTP block
    BOOST_CHECK_MESSAGE(DisconnectBlocks(1), "Block disconnect failed");
    {
        CValidationState state;
        const CChainParams& chainparams = Params();
        InvalidateBlock(state, chainparams, mapBlockIndex[b.GetHash()]);
    }
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height() + 1, "Block not disconnected");



    //Change MTP switch time to make next block be non-mtp
    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(GetAdjustedTime() + 1000000);
    mtp = false;

    previousHeight = chainActive.Height();

    b = CreateAndProcessBlock(noTxns, scriptPubKeyMtp, mtp);
    coinbaseTxns.push_back(b.vtx[0]);
    {
        LOCK(pwalletMain->cs_wallet);
        pwalletMain->AddToWalletIfInvolvingMe(b.vtx[0], &b, true);
    }

    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height() - 1, "Block not connected");

    //Now again add a new MTP block
    mtp = true;
    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(GetAdjustedTime());

    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock(noTxns, scriptPubKeyMtp, mtp);
    coinbaseTxns.push_back(b.vtx[0]);
    {
        LOCK(pwalletMain->cs_wallet);
        pwalletMain->AddToWalletIfInvolvingMe(b.vtx[0], &b, true);
    }

    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(INT_MAX);

    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height() - 1, "Block not connected");

}

BOOST_AUTO_TEST_SUITE_END()
