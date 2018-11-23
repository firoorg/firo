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
#include "znodeman.h"
#include "znode-sync.h"
#include "znode-payments.h"

#include "test/testutil.h"
#include "consensus/merkle.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

extern CCriticalSection cs_main;
using namespace std;

CScript scriptPubKeyZnode;


struct ZnodeTestingSetup : public TestingSetup {
    ZnodeTestingSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        CPubKey newKey;
        BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

        string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        printf("Balance before %ld\n", pwalletMain->GetBalance());
        scriptPubKeyZnode = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        bool mtp = false;
        CBlock b;
        for (int i = 0; i < 150; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKeyZnode, mtp);
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
                       const CScript& scriptPubKeyZnode, bool mtp = false) {
        const CChainParams& chainparams = Params();
        CBlockTemplate *pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKeyZnode);
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
    // scriptPubKeyZnode, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
                                 const CScript& scriptPubKeyZnode, bool mtp = false){

        CBlock block = CreateBlock(txns, scriptPubKeyZnode, mtp);
        BOOST_CHECK_MESSAGE(ProcessBlock(block), "Processing block failed");
        return block;
    }

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

BOOST_FIXTURE_TEST_SUITE(znode_tests, ZnodeTestingSetup)

BOOST_AUTO_TEST_CASE(Test_EnforceZnodePayment)
{

    std::vector<CMutableTransaction> noTxns;
    CBlock b = CreateAndProcessBlock(noTxns, scriptPubKeyZnode, false);
    const CChainParams& chainparams = Params();

    CTransaction& tx = b.vtx[0];
    bool mutated;
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }

    BOOST_CHECK(tx.IsCoinBase());

    CValidationState state;
    BOOST_CHECK(true == CheckBlock(b, state, chainparams.GetConsensus()));
    //BOOST_CHECK(true == CheckTransaction(tx, state, tx.GetHash(), false, INT_MAX));

    auto const before_block = ZC_ZNODE_PAYMENT_BUG_FIXED_AT_BLOCK
             , after_block = ZC_ZNODE_PAYMENT_BUG_FIXED_AT_BLOCK + 1;
    // Emulates synced state of znodes.
    for(size_t i =0; i < 4; ++i)
        znodeSync.SwitchToNextAsset();


    ///////////////////////////////////////////////////////////////////////////
    // Paying to the best payee
    CZnodePayee payee1(tx.vout[1].scriptPubKey, uint256());
    // Emulates 6 votes for the payee
    for(size_t i =0; i < 5; ++i)
        payee1.AddVoteHash(uint256());

    CZnodeBlockPayees payees;
    payees.vecPayees.push_back(payee1);

    mnpayments.mapZnodeBlocks[after_block] = payees;

    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(true == CheckBlock(b, state, chainparams.GetConsensus()));
    BOOST_CHECK(true == CheckTransaction(tx, state, tx.GetHash(), false, after_block));


    ///////////////////////////////////////////////////////////////////////////
    // Paying to a completely wrong payee
    tx.vout[1].scriptPubKey = tx.vout[0].scriptPubKey;
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(false == CheckBlock(b, state, chainparams.GetConsensus()));
    BOOST_CHECK(true == CheckTransaction(tx, state, tx.GetHash(), false, after_block));


    ///////////////////////////////////////////////////////////////////////////
    // Making znodes not synchronized and checking the functionality is disabled
    znodeSync.Reset();
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(true == CheckTransaction(tx, state, tx.GetHash(), false, after_block));


    ///////////////////////////////////////////////////////////////////////////
    // Paying to an acceptable payee
    for(size_t i =0; i < 4; ++i)
        znodeSync.SwitchToNextAsset();

    CZnodePayee payee2(tx.vout[0].scriptPubKey, uint256());
    // Emulates 9 votes for the payee
    for(size_t i =0; i < 8; ++i)
        payee2.AddVoteHash(uint256());

    mnpayments.mapZnodeBlocks[after_block].vecPayees.insert(mnpayments.mapZnodeBlocks[after_block].vecPayees.begin(), payee2);

    tx.vout[1].scriptPubKey = payee1.GetPayee();
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(true == CheckBlock(b, state, chainparams.GetConsensus()));
    BOOST_CHECK(true == CheckTransaction(tx, state, tx.GetHash(), false, after_block));


    ///////////////////////////////////////////////////////////////////////////
    // Checking the functionality is disabled for previous blocks
    tx.vout[1].scriptPubKey = tx.vout[2].scriptPubKey;
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(false == CheckBlock(b, state, chainparams.GetConsensus()));
    BOOST_CHECK(true == CheckTransaction(tx, state, tx.GetHash(), false, after_block));

    mnpayments.mapZnodeBlocks[before_block] = payees;

    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(true == CheckTransaction(tx, state, tx.GetHash(), false, before_block));
}



BOOST_AUTO_TEST_SUITE_END()
