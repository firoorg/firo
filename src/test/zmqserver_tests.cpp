    // Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
#include "main.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "znode-sync.h"
#include "znodeconfig.h"

#include "zmqserver/zmqinterface.h"
#include "zmqserver/zmqabstract.h"

#include "validationinterface.h"

using namespace std;
extern CCriticalSection cs_main;

static CZMQPublisherInterface* pzmqPublisherInterface = NULL;
static CZMQReplierInterface* pzmqReplierInterface = NULL;

void *pOpenSocket;
void *pAuthSocket;
void *pSubSocket;

string openPort = "25558";
string authPort = "35557";

int numSubTests = 1;

struct ZmqServerTestingSetup : public TestingSetup {
    ZmqServerTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {

        CZMQAbstract::createCerts(true);

        pzmqPublisherInterface = CZMQPublisherInterface::Create();
        pzmqReplierInterface = CZMQReplierInterface::Create();
 
        // zregister publisher with validation interface
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

        string address = "tcp://127.0.0.1:38332";
        int rc = zmq_connect(pSubSocket, address.c_str());
        BOOST_CHECK(rc!=-1);

        string option = "block";
        zmq_setsockopt (pSubSocket, ZMQ_SUBSCRIBE, option.c_str(), option.length());
        cout << "ZMQ: setsockopt complete" << endl;

        zmq_msg_t topic;
        zmq_msg_t contents;
        int a;
        int testCount = 0;
        while(testCount < numSubTests){
            rc = zmq_msg_init (&topic);
            a = zmq_msg_init (&contents);
            cout << "ZMQ: receiving msg.." << endl;
            rc = zmq_msg_recv (&topic, pSubSocket, 0);
            a = zmq_msg_recv (&contents, pSubSocket, 0);
            cout << "ZMQ: received" << endl;

            char* topicChars = (char*) malloc (rc + 1);
            char* contentsChars = (char*) malloc (a + 1);
            memcpy (topicChars, zmq_msg_data (&topic), rc);
            memcpy (contentsChars, zmq_msg_data (&contents), a);
            zmq_msg_close(&topic);
            zmq_msg_close(&contents);

            cout << "option: " << option << endl;
            cout << "topicChars: " << topicChars << endl;

            // remove trailing whitespace
            topicChars[strlen(topicChars)-1] = 0;

            std::string topicStr = std::string(topicChars);
            BOOST_CHECK(topicStr==option);

            testCount++;
        }

        zmq_close (pSubSocket);
        zmq_ctx_destroy (pcontext);
    }

    void InitializeRequester(bool isAuth) {
        void * pcontext;
        pcontext = zmq_init(1);
        BOOST_CHECK(pcontext);

        cout << "ZMQ: created pcontext" << endl;
        string port;
        if(isAuth){
            pAuthSocket = zmq_socket(pcontext,ZMQ_REQ);
            port = authPort;
        }else{
            pOpenSocket = zmq_socket(pcontext,ZMQ_REQ);
            port = openPort;            
        }
        void* psocket = (isAuth) ? pAuthSocket : pOpenSocket;
        BOOST_CHECK(psocket);

        string address = "tcp://127.0.0.1:";
        address.append(port);

        int rc = zmq_connect(psocket, address.c_str());
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

        cout << std::string(requestChars) << endl;
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
};

BOOST_FIXTURE_TEST_SUITE(zmqserver_tests, ZmqServerTestingSetup)

BOOST_AUTO_TEST_CASE(open_test)
{
    UniValue requestUni(UniValue::VOBJ);
    requestUni.push_back(Pair("type", "initial"));
    requestUni.push_back(Pair("collection", "apiStatus"));
    SendRequest(requestUni, pOpenSocket);

    ReadResponse(pOpenSocket);
}

// publisher interface sends 
BOOST_AUTO_TEST_CASE(status_test)
{
    boost::thread* worker;
    worker = new boost::thread(boost::bind(&ZmqServerTestingSetup::InitializeSubscriber, this));
    cout << "started worker. waiting for setup.." << endl;
    boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
    cout << "Calling sync status & waiting.." << endl;
    GetMainSignals().UpdateSyncStatus();
    boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
}

// Straightforward way of running a function post-tests.
BOOST_AUTO_TEST_CASE(shutdown)
{    
   Shutdown();
}

BOOST_AUTO_TEST_SUITE_END()
