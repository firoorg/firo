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
#include "consensus/merkle.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>

extern CCriticalSection cs_main;
using namespace std;

CScript scriptPubKeyMtpMalformed;

bool no_check( std::runtime_error const& ex );

struct MtpMalformedTestingSetup : public TestingSetup {
    MtpMalformedTestingSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        CPubKey newKey;
        BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

        string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        printf("Balance before %ld\n", pwalletMain->GetBalance());
        scriptPubKeyMtpMalformed = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        bool mtp = false;
        CBlock b;
        for (int i = 0; i < 150; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKeyMtpMalformed, mtp);
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
                       const CScript& scriptPubKeyMtpMalformed, bool mtp = false) {
        const CChainParams& chainparams = Params();
        CBlockTemplate *pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKeyMtpMalformed);
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
    // scriptPubKeyMtpMalformed, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
                                 const CScript& scriptPubKeyMtpMalformed, bool mtp = false){

        CBlock block = CreateBlock(txns, scriptPubKeyMtpMalformed, mtp);
        BOOST_CHECK_MESSAGE(ProcessBlock(block), "Processing block failed");
        return block;
    }

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

BOOST_FIXTURE_TEST_SUITE(mtp_malformed_tests, MtpMalformedTestingSetup)

BOOST_AUTO_TEST_CASE(mtp_malformed)
{
    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(INT_MAX);
    bool mtp = false;
    CBlock b;
    //Good check to have
    BOOST_CHECK_MESSAGE(!b.fChecked, "fChecked must be initialized to false");
    //const CChainParams& chainparams = Params();

    std::vector<CMutableTransaction> noTxns;
    b = CreateBlock(noTxns, scriptPubKeyMtpMalformed, mtp);
    CAmount blockReward = 0;
    for(auto txout : b.vtx[0].vout)
        blockReward += txout.nValue;
    BOOST_CHECK_MESSAGE(blockReward == 50 * COIN, "Block reward not correct in MTP block");
    CBlock oldBlock = b;

    int previousHeight = chainActive.Height();
    ProcessBlock(b);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height() - 1, "Block not connected");

    //Transition to MTP
    mtp = true;
    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(GetAdjustedTime());

    CBlock bMtp = CreateBlock(noTxns, scriptPubKeyMtpMalformed, mtp);
    previousHeight = chainActive.Height();
    memset(bMtp.mtpHashData->hashRootMTP, 0, sizeof(bMtp.mtpHashData->hashRootMTP));
    memset(bMtp.mtpHashData->nBlockMTP, 0, sizeof(bMtp.mtpHashData->nBlockMTP));
    for(unsigned int i = 0; i < 192; i++)
        for(unsigned int j = 0; j < bMtp.mtpHashData->nProofMTP[i].size(); j++)
            for(unsigned int k = 0; k < bMtp.mtpHashData->nProofMTP[i][j].size(); k++)
                bMtp.mtpHashData->nProofMTP[i][j][k] = 0;
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with incorrect proof");

    bMtp = CreateBlock(noTxns, scriptPubKeyMtpMalformed, mtp);
    bMtp.mtpHashData = make_shared<CMTPHashData>();
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with missing proof");


    bMtp = CreateBlock(noTxns, scriptPubKeyMtpMalformed, mtp);
    for(unsigned int i = 0; i < 192; i++)
        for(unsigned int j = 0; j < bMtp.mtpHashData->nProofMTP[i].size(); j++)
            for(unsigned int k = 0; k < bMtp.mtpHashData->nProofMTP[i][j].size(); k++)
                bMtp.mtpHashData->nProofMTP[i][j][k] = 0;
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with missing proof");

    bMtp = CreateBlock(noTxns, scriptPubKeyMtpMalformed, mtp);
    previousHeight = chainActive.Height();
    for(unsigned int i = 0; i < sizeof(bMtp.mtpHashData->hashRootMTP); i++)
        bMtp.mtpHashData->hashRootMTP[i] = rand()%256;
    for(unsigned int i = 0; i < mtp::MTP_L*2; i++)
        for(unsigned int j = 0; j < 128; j++)
        bMtp.mtpHashData->nBlockMTP[i][j] = rand();
    for(unsigned int i = 0; i < 192; i++)
        for(unsigned int j = 0; j < bMtp.mtpHashData->nProofMTP[i].size(); j++)
            for(unsigned int k = 0; k < bMtp.mtpHashData->nProofMTP[i][j].size(); k++)
                bMtp.mtpHashData->nProofMTP[i][j][k] = rand()%256;
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with incorrect proof");

    bMtp = CreateBlock(noTxns, scriptPubKeyMtpMalformed, mtp);
    previousHeight = chainActive.Height();
    for(unsigned int i = 0; i < 192; i++)
        for(unsigned int j = 0; j < bMtp.mtpHashData->nProofMTP[i].size(); j++)
            bMtp.mtpHashData->nProofMTP[i][j].resize(bMtp.mtpHashData->nProofMTP[i][j].size()/2);
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with incorrect proof");

    bMtp = CreateBlock(noTxns, scriptPubKeyMtpMalformed, mtp);
    CDataStream mybufstream(SER_NETWORK, PROTOCOL_VERSION);
    mybufstream << *bMtp.mtpHashData;
    CMTPHashData outh;
    mybufstream >> outh;
    BOOST_CHECK_MESSAGE(memcmp(outh.hashRootMTP, bMtp.mtpHashData->hashRootMTP, sizeof(outh.hashRootMTP))
        == 0, "Serialize does not match unserialize");
    BOOST_CHECK_MESSAGE(memcmp(outh.nBlockMTP, bMtp.mtpHashData->nBlockMTP, sizeof(outh.nBlockMTP))
        == 0, "Serialize does not match unserialize");
    for(unsigned int i = 0; i < 192; i++)
        for(unsigned int j = 0; j < bMtp.mtpHashData->nProofMTP[i].size(); j++)
            for(unsigned int k = 0; k < bMtp.mtpHashData->nProofMTP[i][j].size(); k++)
                BOOST_CHECK_MESSAGE(outh.nProofMTP[i][j][k] == bMtp.mtpHashData->nProofMTP[i][j][k],
                     "Serialize does not match unserialize");

    mybufstream.clear();
    mybufstream << *bMtp.mtpHashData;
    mybufstream.insert(mybufstream.begin(), 0);
    BOOST_CHECK_EXCEPTION(mybufstream >> outh, std::runtime_error, no_check);

    mybufstream.clear();
    mybufstream << *bMtp.mtpHashData;
    for(auto &it : mybufstream)
        it = 0;
    mybufstream >> outh;//This passes and creates empty object

    mybufstream.clear();
    mybufstream << *bMtp.mtpHashData;
    for(auto &it : mybufstream)
        it = rand()%256;
    BOOST_CHECK_EXCEPTION(mybufstream >> outh, std::runtime_error, no_check);

    mybufstream.clear();
    mybufstream << *bMtp.mtpHashData;
    mybufstream.resize(mybufstream.size()/2);
    BOOST_CHECK_EXCEPTION(mybufstream >> outh, std::runtime_error, no_check);
    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(INT_MAX);
}

BOOST_AUTO_TEST_SUITE_END()
