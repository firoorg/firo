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
#include "test/fixtures.h"
#include "consensus/merkle.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>

#include <ios>

BOOST_FIXTURE_TEST_SUITE(mtp_malformed_tests, MtpMalformedTestingSetup)

BOOST_AUTO_TEST_CASE(mtp_malformed)
{
    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(INT_MAX);
    bool mtp = false;
    CBlock b;
    //Good check to have
    BOOST_CHECK_MESSAGE(!b.fChecked, "fChecked must be initialized to false");
    //const CChainParams& chainparams = Params();

    b = CreateBlock({}, scriptPubKey, mtp);
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

    CBlock bMtp = CreateBlock({}, scriptPubKey, mtp);
    previousHeight = chainActive.Height();
    memset(bMtp.mtpHashData->hashRootMTP, 0, sizeof(bMtp.mtpHashData->hashRootMTP));
    memset(bMtp.mtpHashData->nBlockMTP, 0, sizeof(bMtp.mtpHashData->nBlockMTP));
    for(unsigned int i = 0; i < 192; i++)
        for(unsigned int j = 0; j < bMtp.mtpHashData->nProofMTP[i].size(); j++)
            for(unsigned int k = 0; k < bMtp.mtpHashData->nProofMTP[i][j].size(); k++)
                bMtp.mtpHashData->nProofMTP[i][j][k] = 0;
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with incorrect proof");

    bMtp = CreateBlock({}, scriptPubKey, mtp);
    bMtp.mtpHashData = make_shared<CMTPHashData>();
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with missing proof");


    bMtp = CreateBlock({}, scriptPubKey, mtp);
    for(unsigned int i = 0; i < 192; i++)
        for(unsigned int j = 0; j < bMtp.mtpHashData->nProofMTP[i].size(); j++)
            for(unsigned int k = 0; k < bMtp.mtpHashData->nProofMTP[i][j].size(); k++)
                bMtp.mtpHashData->nProofMTP[i][j][k] = 0;
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with missing proof");

    bMtp = CreateBlock({}, scriptPubKey, mtp);
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

    bMtp = CreateBlock({}, scriptPubKey, mtp);
    previousHeight = chainActive.Height();
    for(unsigned int i = 0; i < 192; i++)
        for(unsigned int j = 0; j < bMtp.mtpHashData->nProofMTP[i].size(); j++)
            bMtp.mtpHashData->nProofMTP[i][j].resize(bMtp.mtpHashData->nProofMTP[i][j].size()/2);
    ProcessBlock(bMtp);
    BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Block connected with incorrect proof");

    bMtp = CreateBlock({}, scriptPubKey, mtp);
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
    BOOST_CHECK_EXCEPTION(mybufstream >> outh, std::ios_base::failure, [](const std::ios_base::failure&) { return true; });

    mybufstream.clear();
    mybufstream << *bMtp.mtpHashData;
    for(auto &it : mybufstream)
        it = 0;
    mybufstream >> outh;//This passes and creates empty object

    mybufstream.clear();
    mybufstream << *bMtp.mtpHashData;
    for(auto &it : mybufstream)
        it = rand()%256;
    BOOST_CHECK_EXCEPTION(mybufstream >> outh, std::ios_base::failure, [](const std::ios_base::failure&) { return true; });

    mybufstream.clear();
    mybufstream << *bMtp.mtpHashData;
    mybufstream.resize(mybufstream.size()/2);
    BOOST_CHECK_EXCEPTION(mybufstream >> outh, std::ios_base::failure, [](const std::ios_base::failure&) { return true; });
    Params(CBaseChainParams::REGTEST).SetRegTestMtpSwitchTime(INT_MAX);
}

BOOST_AUTO_TEST_SUITE_END()
