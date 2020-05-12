    // Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <algorithm>

#include "client-api/wallet.h"
#include "client-api/server.h"
#include "client-api/protocol.h"
#include "client-api/register.h"

#include "wallet/rpcwallet.h"

#include "base58.h"
#include "netbase.h"

#include "test/test_bitcoin.h"

#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include "miner.h"
#include "validation.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "znode-sync.h"
#include "znodeconfig.h"

#include "zmqserver/zmqinterface.h"
#include "zmqserver/zmqabstract.h"

#include "znodeman.h"
#include "znode.h"

#include "validationinterface.h"

#include <boost/algorithm/string.hpp>

using namespace std;
extern CCriticalSection cs_main;

static CZMQPublisherInterface* pzmqPublisherInterface = NULL;
static CZMQReplierInterface* pzmqReplierInterface = NULL;

void *pOpenSocket;
void *pAuthSocket;
void *pSubSocket;

CScript scriptPubKeyZmqServer;

struct ZmqServerTestingSetup : public TestingSetup {
    ZmqServerTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {
        uiInterface.InitMessage.connect(SetAPIWarmupStatus);

        CPubKey newKey;
        BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

        string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        printf("Balance before %ld\n", pwalletMain->GetBalance());
        scriptPubKeyZmqServer = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        bool mtp = false;
        CBlock b;
        for (int i = 0; i < 150; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            b = CreateAndProcessBlock(noTxns, scriptPubKeyZmqServer, mtp);
            coinbaseTxns.push_back(b.vtx[0]);
            LOCK(cs_main);
            {
                LOCK(pwalletMain->cs_wallet);
                pwalletMain->AddToWalletIfInvolvingMe(b.vtx[0], &b, true);
            }   
        }
        printf("Balance after 150 blocks: %ld\n", pwalletMain->GetBalance());

        SetAPIWarmupFinished();

        CZMQAbstract::CreateCerts(true);

        pzmqPublisherInterface = pzmqPublisherInterface->Create();
        pzmqReplierInterface = pzmqReplierInterface->Create();
 
        // register publisher with validation interface
        RegisterValidationInterface(pzmqPublisherInterface);

        // set up requester for ZMQ replier.
        InitializeRequester(true);
        InitializeRequester(false);

    }

    void* InitializeSubscriber() {
        void * pcontext;
        pcontext = zmq_init(1);
        BOOST_CHECK(pcontext);

        cout << "ZMQ: created pcontext" << endl;
        pSubSocket = zmq_socket(pcontext,ZMQ_SUB);
        BOOST_CHECK(pSubSocket);

        if(CZMQAbstract::DEV_AUTH){
            vector<string> clientKeys = CZMQAbstract::ReadCert(CZMQAbstract::Client);
            vector<string> serverKeys = CZMQAbstract::ReadCert(CZMQAbstract::Server);

            string server_key = serverKeys.at(0);
            string secret_key = clientKeys.at(1);
            string public_key = clientKeys.at(0);
            
            const int curve_server_enable = 1;
            zmq_setsockopt(pSubSocket, ZMQ_CURVE_SERVER, &curve_server_enable, sizeof(curve_server_enable));
            zmq_setsockopt(pSubSocket, ZMQ_CURVE_SERVERKEY, server_key.c_str(), 40);
            zmq_setsockopt(pSubSocket, ZMQ_CURVE_SECRETKEY, secret_key.c_str(), 40);
            zmq_setsockopt(pSubSocket, ZMQ_CURVE_PUBLICKEY, public_key.c_str(), 40); 
        }

        string address = BaseParams().APIAddr() + to_string(BaseParams().APIAuthPUBPort());
        int rc = zmq_connect(pSubSocket, address.c_str());
        BOOST_CHECK(rc!=-1);

        // push in op
        vector<string> topics;
        vector<string> topicsCalled;

        topics.push_back("block");
        topics.push_back("mintStatus");
        topics.push_back("address");
        topics.push_back("balance");
        topics.push_back("transaction");

        BOOST_FOREACH(string topic, topics)
            zmq_setsockopt (pSubSocket, ZMQ_SUBSCRIBE, topic.c_str(), topic.length());

        cout << "ZMQ: setsockopt complete" << endl;

        zmq_msg_t topicCalled;
        zmq_msg_t contents;
        zmq_msg_t nonce;
        int a;
        int b;
        while(true){
            rc = zmq_msg_init (&topicCalled);
            a = zmq_msg_init (&contents);
            b = zmq_msg_init (&nonce);
            cout << "ZMQ: receiving msg.." << endl;
            rc = zmq_msg_recv (&topicCalled, pSubSocket, 0);
            a = zmq_msg_recv (&contents, pSubSocket, 0);
            b = zmq_msg_recv (&nonce, pSubSocket, 0);
            cout << "ZMQ: received" << endl;

            char* topicChars = (char*) malloc (rc + 1);
            char* contentsChars = (char*) malloc (a + 1);
            memcpy (topicChars, zmq_msg_data (&topicCalled), rc);
            memcpy (contentsChars, zmq_msg_data (&contents), a);
            zmq_msg_close(&topicCalled);
            zmq_msg_close(&contents);
            zmq_msg_close(&nonce);
            
            std::string topicStr = std::string(topicChars);

            cout << "topicCalled: " << topicStr << endl;
            cout << "contents:" << contentsChars << endl;
            topicsCalled.push_back(topicStr);

            bool found = false;
            BOOST_FOREACH(string topic, topics){   
                if(topicStr.find(topic) != std::string::npos){
                    found = true;
                    break;
                }
            }
            BOOST_CHECK(found);
        }

        zmq_close (pSubSocket);
        zmq_ctx_destroy (pcontext);
    }

    void InitializeRequester(bool isAuth) {
        void * pcontext;
        pcontext = zmq_init(1);
        BOOST_CHECK(pcontext);

        cout << "ZMQ: created pcontext" << endl;
        if(isAuth){
            pAuthSocket = zmq_socket(pcontext,ZMQ_REQ);
        }else{
            pOpenSocket = zmq_socket(pcontext,ZMQ_REQ);
        }
        BOOST_CHECK((isAuth) ? pAuthSocket : pOpenSocket);

        if(CZMQAbstract::DEV_AUTH && isAuth){
            vector<string> clientKeys = CZMQAbstract::ReadCert(CZMQAbstract::Client);
            vector<string> serverKeys = CZMQAbstract::ReadCert(CZMQAbstract::Server);

            string server_key = serverKeys.at(0);
            string secret_key = clientKeys.at(1);
            string public_key = clientKeys.at(0);
            
            const int curve_server_enable = 1;
            zmq_setsockopt(pAuthSocket, ZMQ_CURVE_SERVER, &curve_server_enable, sizeof(curve_server_enable));
            zmq_setsockopt(pAuthSocket, ZMQ_CURVE_SERVERKEY, server_key.c_str(), 40);
            zmq_setsockopt(pAuthSocket, ZMQ_CURVE_SECRETKEY, secret_key.c_str(), 40);
            zmq_setsockopt(pAuthSocket, ZMQ_CURVE_PUBLICKEY, public_key.c_str(), 40);   
        }

        string address = BaseParams().APIAddr();
        string port = isAuth ? to_string(BaseParams().APIAuthREPPort()) : 
                               to_string(BaseParams().APIOpenREPPort());
        address.append(port);

        int rc = zmq_connect((isAuth) ? pAuthSocket : pOpenSocket, address.c_str());
        BOOST_CHECK(rc!=-1);
        cout << "ZMQ: connected to psocket" << endl;
    }

    void SendRequest(UniValue requestUni, void* psocket) {
        string request = requestUni.write();
        cout << "request:" << request << endl;

        zmq_msg_t msg;
        int rc = zmq_msg_init_size(&msg, request.length());
        BOOST_CHECK(rc!=-1);
        cout << "ZMQ: init msg" << endl;

        void *buf = zmq_msg_data(&msg);
        memcpy(buf, request.c_str(), request.length());

        rc = zmq_msg_send(&msg, psocket, 0);
        BOOST_CHECK(rc!=-1);
        cout << "ZMQ: sent msg" << endl;
    }

    void ReadResponse(void* psocket) {
        zmq_msg_t buffer;
        int rc = zmq_msg_init (&buffer);
        BOOST_CHECK(rc!=-1);
        cout << "ZMQ: init buffer" << endl;

        rc = zmq_recvmsg(psocket, &buffer, 0);
        BOOST_CHECK(rc!=-1);
        cout << "ZMQ: received msg" << endl;

        char* requestChars = (char*) malloc (rc + 1);
        memcpy (requestChars, zmq_msg_data (&buffer), rc);
        zmq_msg_close(&buffer);

        // cout << std::string(requestChars) << endl;
    }

    void Shutdown(){
        if (pzmqPublisherInterface) {
            UnregisterValidationInterface(pzmqPublisherInterface);
            delete pzmqPublisherInterface;
            pzmqPublisherInterface = NULL;
        }

        if (pzmqReplierInterface) {
            delete pzmqReplierInterface;
            pzmqReplierInterface = NULL;
        }
    }

    ~ZmqServerTestingSetup(){
        Shutdown();
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

BOOST_FIXTURE_TEST_SUITE(zmqserver_tests, ZmqServerTestingSetup)

// publisher interface triggering events - verified in subscriber thread
BOOST_AUTO_TEST_CASE(event_tests)
{
    boost::thread* worker;
    UniValue mintUpdates(UniValue::VOBJ);
    UniValue entry(UniValue::VOBJ);


    worker = new boost::thread(boost::bind(&ZmqServerTestingSetup::InitializeSubscriber, this));
    cout << "started worker. waiting 10 seconds for daemon setup.." << endl;
    boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
    cout << "Calling events and waiting.." << endl;

    // Connections
    cout << "Calling NumConnectionsChanged.." << endl;
    GetMainSignals().NumConnectionsChanged();
    boost::this_thread::sleep_for(boost::chrono::milliseconds(100));

    // // mintUpdates
    entry.push_back(Pair("available", false));
    // use an arbitrary hash for the index.
    mintUpdates.push_back(Pair(chainActive.Tip()->phashBlock->ToString(), entry));
    cout << "Calling UpdatedMintStatus.." << endl;
    GetMainSignals().UpdatedMintStatus(mintUpdates.write());
    boost::this_thread::sleep_for(boost::chrono::milliseconds(100));

    // Sync Status
    cout << "Calling UpdateSyncStatus.." << endl;
    GetMainSignals().UpdateSyncStatus();
    boost::this_thread::sleep_for(boost::chrono::milliseconds(100));

    // updated block tip
    cout << "Calling UpdatedBlockTip.." << endl;
    GetMainSignals().UpdatedBlockTip(chainActive.Tip());
    boost::this_thread::sleep_for(boost::chrono::milliseconds(100));

    // SyncTransaction
    CBlock block;
    ReadBlockFromDisk(block, chainActive.Tip(), Params().GetConsensus());
    cout << "Calling SyncWithWallets.." << endl;
    SyncWithWallets(block.vtx[0], NULL, NULL);

    // allow an extra bit of time for subscriber to finish
    boost::this_thread::sleep_for(boost::chrono::milliseconds(4000));
}

BOOST_AUTO_TEST_CASE(open_test)
{
    UniValue requestUni(UniValue::VOBJ);
    requestUni.push_back(Pair("type", "initial"));
    requestUni.push_back(Pair("collection", "apiStatus"));
    SendRequest(requestUni, pOpenSocket);

    ReadResponse(pOpenSocket);
}

BOOST_AUTO_TEST_CASE(auth_test)
{
    InitializeRequester(true);
    UniValue requestUni(UniValue::VOBJ);
    requestUni.push_back(Pair("type", "initial"));
    requestUni.push_back(Pair("collection", "stateWallet"));
    SendRequest(requestUni, pAuthSocket);

    ReadResponse(pAuthSocket);
}

BOOST_AUTO_TEST_SUITE_END()
