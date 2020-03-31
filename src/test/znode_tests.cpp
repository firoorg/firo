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

        scriptPubKeyZnode = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        bool mtp = false;
        CBlock b;
        for (int i = 0; i < 150; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKeyZnode, mtp);
            coinbaseTxns.push_back(*b.vtx[0]);
            LOCK(cs_main);
            {
                LOCK(pwalletMain->cs_wallet);
                pwalletMain->AddToWalletIfInvolvingMe(*b.vtx[0], chainActive.Tip(), 0, true);
            }   
        }
    }

    CBlock CreateBlock(const std::vector<CMutableTransaction>& txns,
                       const CScript& scriptPubKeyZnode, bool mtp = false) {
        const CChainParams& chainparams = Params();
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKeyZnode);
        CBlock block = pblocktemplate->block;

        // Replace mempool-selected txns with just coinbase plus passed-in txns:
        if(txns.size() > 0) {
            block.vtx.resize(1);
            BOOST_FOREACH(const CMutableTransaction& tx, txns)
                block.vtx.push_back(MakeTransactionRef(tx));
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

    bool ProcessBlock(const CBlock &block) {
        const CChainParams& chainparams = Params();
        return ProcessNewBlock(chainparams, std::make_shared<const CBlock>(block), true, NULL);
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

namespace {
    size_t FindZnodeOutput(CTransaction const & tx) {
        static std::vector<CScript> const founders {
            GetScriptForDestination(CBitcoinAddress("TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo").Get()),
            GetScriptForDestination(CBitcoinAddress("TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5").Get()),
            GetScriptForDestination(CBitcoinAddress("TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT").Get()),
            GetScriptForDestination(CBitcoinAddress("TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve").Get()),
            GetScriptForDestination(CBitcoinAddress("TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS").Get()),
        };

        BOOST_CHECK(tx.IsCoinBase());
        for(size_t i = 0; i < tx.vout.size(); ++i) {
            CTxOut const & out = tx.vout[i];
             if(std::find(founders.begin(), founders.end(), out.scriptPubKey) == founders.end()) {
                if(out.nValue == GetZnodePayment(Params().GetConsensus(), false))
                    return i;
            }
        }
        throw std::runtime_error("Cannot find the Znode output");
    }
}
BOOST_AUTO_TEST_CASE(Test_EnforceZnodePayment)
{

    std::vector<CMutableTransaction> noTxns;
    CBlock b = CreateAndProcessBlock(noTxns, scriptPubKeyZnode, false);
    const CChainParams& chainparams = Params();

    CMutableTransaction tx = *b.vtx[0];
    bool mutated;
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }

    BOOST_CHECK(CTransaction(tx).IsCoinBase());

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

    znpayments.mapZnodeBlocks[after_block] = payees;

    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(true == CheckBlock(b, state, chainparams.GetConsensus()));
    BOOST_CHECK(true == CheckTransaction(tx, state, true, tx.GetHash(), false, after_block));


    ///////////////////////////////////////////////////////////////////////////
    // Paying to a completely wrong payee
    size_t const znodeOutput = FindZnodeOutput(tx);
    CMutableTransaction txCopy = tx;
    txCopy.vout[znodeOutput].scriptPubKey = txCopy.vout[0].scriptPubKey;
    b.vtx[0] = MakeTransactionRef(txCopy);
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(false == CheckBlock(b, state, chainparams.GetConsensus(), true, true, after_block));
    BOOST_CHECK(true == CheckTransaction(*b.vtx[0], state, true, tx.GetHash(), false, after_block));


    ///////////////////////////////////////////////////////////////////////////
    // Making znodes not synchronized and checking the functionality is disabled
    CTxOut storedCopy = tx.vout[znodeOutput];
    tx.vout.erase(tx.vout.begin() + znodeOutput);
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }

    BOOST_CHECK(false == CheckBlock(b, state, chainparams.GetConsensus(), true, true, after_block));
    BOOST_CHECK(true == CheckTransaction(*b.vtx[0], state, true, tx.GetHash(), false, after_block));

    tx.vout.insert(tx.vout.begin() + znodeOutput, storedCopy);


    ///////////////////////////////////////////////////////////////////////////
    // Removing the znode payment
    znodeSync.Reset();
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(true == CheckTransaction(*b.vtx[0], state, true, tx.GetHash(), false, after_block));


    ///////////////////////////////////////////////////////////////////////////
    // Paying to an acceptable payee
    for(size_t i =0; i < 4; ++i)
        znodeSync.SwitchToNextAsset();

    CZnodePayee payee2(tx.vout[0].scriptPubKey, uint256());
    // Emulates 9 votes for the payee
    for(size_t i =0; i < 8; ++i)
        payee2.AddVoteHash(uint256());

    znpayments.mapZnodeBlocks[after_block].vecPayees.insert(znpayments.mapZnodeBlocks[after_block].vecPayees.begin(), payee2);

    txCopy.vout[1].scriptPubKey = payee1.GetPayee();
    b.vtx[0] = MakeTransactionRef(txCopy);
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(true == CheckBlock(b, state, chainparams.GetConsensus()));
    BOOST_CHECK(true == CheckTransaction(*b.vtx[0], state, true, tx.GetHash(), false, after_block));


    ///////////////////////////////////////////////////////////////////////////
    // Checking the functionality is disabled for previous blocks
    txCopy.vout[1].scriptPubKey = txCopy.vout[2].scriptPubKey;
    b.vtx[0] = MakeTransactionRef(txCopy);
    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(false == CheckBlock(b, state, chainparams.GetConsensus()));
    BOOST_CHECK(true == CheckTransaction(*b.vtx[0], state, true, tx.GetHash(), false, after_block));

    znpayments.mapZnodeBlocks[before_block] = payees;

    b.fChecked = false;
    b.hashMerkleRoot = BlockMerkleRoot(b, &mutated);
    while (!CheckProofOfWork(b.GetHash(), b.nBits, chainparams.GetConsensus())){
        ++b.nNonce;
    }
    BOOST_CHECK(true == CheckTransaction(*b.vtx[0], state, true, tx.GetHash(), false, before_block));
}



BOOST_AUTO_TEST_SUITE_END()
