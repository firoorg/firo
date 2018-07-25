#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "client-api/protocol.h"
#include "client-api/server.h"

#include "httpserver.h"
#include "client-api/zmq.h"
#include "zmq/zmqpublishnotifier.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "clientversion.h"
#include "util.h"
#include "utilstrencodings.h"
#include <chrono>
#include "main.h"
#include "httpserver.h"
#ifdef ENABLE_WALLET
#include "znode-sync.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif

#include <boost/filesystem/operations.hpp>
#include <stdio.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <univalue.h>

#include <iostream>
#include <sstream>

/******************* Start REQ/REP ZMQ functions ******************************************/
//TODO create class to hold thread instance. have to experiment with different setups
// public: context, socket, thread
// set threads on each class
// verify requested method can be called with auth port
// few different ways here: http://zeromq.org/topics:binding-abstractions
// polling seems the best bet
// or alternatively just generalize into a separate function, and wait on independant threads.
// also change to boost::threads over pthreads

void *context_auth;
void *socket_auth;

void *context_open;
void *socket_open;

pthread_t worker_auth;
pthread_t worker_open;

zmq_pollitem_t items [2];

void zmqError(const char *str)
{
    LogPrint(NULL, "zmq: Error: %s, errno=%s\n", str, zmq_strerror(errno));
}

// 'Wait' thread. hangs waiting for REQ
bool wait(int& rc, zmq_msg_t& request, bool auth){
    /* Block until a message is available to be received from socket */
    rc = zmq_recvmsg ((auth ? socket_auth : socket_open), &request, 0);
    if(rc==-1) return false; //TODO error handle

    return true;
}

std::string readRequest(int& rc, zmq_msg_t& request){
    char* requestChars = (char*) malloc (rc + 1);
    memcpy (requestChars, zmq_msg_data (&request), rc);
    zmq_msg_close(&request);
    requestChars[rc]=0;
    return std::string(requestChars);
}

bool sendResponse(int& rc, string response, bool auth){
    /* Send reply */
    zmq_msg_t reply;
    rc = zmq_msg_init_size (&reply, response.size());
    assert(rc == 0);  
    std::memcpy (zmq_msg_data (&reply), response.data(), response.size());
    LogPrintf("ZMQ: Sending reply..\n");
    /* Block until a message is available to be sent from socket */   
    rc = zmq_sendmsg ((auth ? socket_auth : socket_open), &reply, 0);    
    if(rc==-1) return false; //TODO error handle

    LogPrintf("ZMQ: Reply sent.\n");
    zmq_msg_close(&reply);

    return true;
}


// bool poll_setup(){
    
//     items[0].socket = socket_auth;
//     items[0].events = ZMQ_POLLIN;
    
//     items[1].socket = context_open;
//     items[1].events = ZMQ_POLLIN;
// }
//     /* Poll for events indefinitely */
//     int rc = zmq_poll (items, 2, -1);
//     assert (rc >= 0); /* Returned events will be stored in items[].revents */
// }


//*********** threads waiting for responses ***********//
static void* threadAuth(void *arg){

    LogPrintf("ZMQ: IN REQREP_ZMQ_auth\n");
    while (1) {
        /* Create an empty ØMQ message to hold the message part. */
        /* message assumed to contain an API command to be executed with data */
        zmq_msg_t request;
        int rc = zmq_msg_init (&request);

        /* Block until a message is available to be received from socket */
        wait(rc, request, true);

        APIJSONRequest jreq;
        string requestStr = readRequest(rc, request);
        std::string response;
        try {
            // Parse request
            UniValue valRequest;
            if (!valRequest.read(requestStr))
                throw JSONAPIError(API_PARSE_ERROR, "Parse error");

            jreq.parse(valRequest);

            UniValue result = tableAPI.execute(jreq, true);

            // Send reply
            response = JSONAPIReply(result, NullUniValue);
            if(!sendResponse(rc, response, true)){
                throw JSONAPIError(API_RESPONSE_ERROR, "Response error");
            }

        } catch (const UniValue& objError) {
            response = JSONAPIReply(NullUniValue, objError);
            sendResponse(rc, response, true);
        } catch (const std::exception& e) {
            response = JSONAPIReply(NullUniValue, JSONAPIError(API_PARSE_ERROR, e.what()));
            sendResponse(rc, response, true);
            return (void*)false;
        }
    }

    return (void*)true;
}

static void* threadOpen(void *arg)
{
    LogPrintf("ZMQ: IN REQREP_ZMQ_open\n");
    while (1) {
        /* Create an empty ØMQ message to hold the message part. */
        /* message assumed to contain an API command to be executed with data */
        zmq_msg_t request;
        int rc = zmq_msg_init (&request);

        /* Block until a message is available to be received from socket */
        wait(rc, request, false);

        APIJSONRequest jreq;
        string requestStr = readRequest(rc, request);
        LogPrintf("API: requestStr: %s\n", requestStr);
        std::string response;
        try {
            // Parse request
            UniValue valRequest;
            if (!valRequest.read(requestStr))
                throw JSONAPIError(API_PARSE_ERROR, "Parse error");

            jreq.parse(valRequest);

            UniValue result = tableAPI.execute(jreq, false);

            // Send reply
            response = JSONAPIReply(result, NullUniValue);
            if(!sendResponse(rc, response, false)){
                throw JSONAPIError(API_RESPONSE_ERROR, "Response error");
            }

        } catch (const UniValue& objError) {
            response = JSONAPIReply(NullUniValue, objError);
            sendResponse(rc, response, false);
        } catch (const std::exception& e) {
            response = JSONAPIReply(NullUniValue, JSONAPIError(API_PARSE_ERROR, e.what()));
            sendResponse(rc, response, false);
            return (void*)false;
        }
    }

    return (void*)true;
}
//*********** threads waiting for responses ***********//


//***** setup ports & call thread *******************//
bool SetupPortOpen(){

    LogPrintf("ZMQ: setting up type.\n");
    context_open = zmq_ctx_new();

    LogPrintf("ZMQ: created context open\n");

    socket_open = zmq_socket(context_open,ZMQ_REP);
    if(!socket_open){
        LogPrintf("ZMQ: Failed to create socket\n");
        return false;
    }
    LogPrintf("ZMQ: created open socket\n");

    // Get network port. TODO add zmq ports to base params
    string port;
    if(Params().NetworkIDString()==CBaseChainParams::MAIN){
      port = "15558";
    }
    else if(Params().NetworkIDString()==CBaseChainParams::TESTNET){
      port = "25558";
    }
    else if(Params().NetworkIDString()==CBaseChainParams::REGTEST){
      port = "35558";
    }

    LogPrintf("ZMQ: port = %s\n", port);

    string tcp = "tcp://*:";

    int rc = zmq_bind(socket_open, tcp.append(port).c_str());
    if (rc == -1)
    {
        LogPrintf("ZMQ: Unable to send ZMQ msg\n");
        return false;
    }
    LogPrintf("ZMQ: Bound socket\n");
  
    pthread_create(&worker_open, NULL, threadOpen, NULL);
    return true;
}

bool SetupPortAuth(){

    LogPrintf("ZMQ: setting up type.\n");
    context_auth = zmq_ctx_new();

    LogPrintf("ZMQ: created context_auths\n");

    socket_auth = zmq_socket(context_auth,ZMQ_REP);
    if(!socket_auth){
        LogPrintf("ZMQ: Failed to create socket_auth\n");
        return false;
    }

    if(DEV_AUTH){
        // set up auth
        vector<string> keys = read_cert("server");

        string server_secret_key = keys.at(1);

        LogPrintf("ZMQ: secret_server_key: %s\n", server_secret_key);

        const int curve_server_enable = 1;
        zmq_setsockopt(socket_auth, ZMQ_CURVE_SERVER, &curve_server_enable, sizeof(curve_server_enable));
        zmq_setsockopt(socket_auth, ZMQ_CURVE_SECRETKEY, server_secret_key.c_str(), 40);
    }


    // Get network port. TODO add zmq ports to base params
    string port;
    if(Params().NetworkIDString()==CBaseChainParams::MAIN){
      port = "15557";
    }
    else if(Params().NetworkIDString()==CBaseChainParams::TESTNET){
      port = "25557";
    }
    else if(Params().NetworkIDString()==CBaseChainParams::REGTEST){
      port = "35557";
    }

    LogPrintf("ZMQ: port = %s\n", port);

    string tcp = "tcp://*:";

    int rc = zmq_bind(socket_auth, tcp.append(port).c_str());
    if (rc == -1)
    {
        LogPrintf("ZMQ: Unable to send ZMQ msg\n");
        return false;
    }
    LogPrintf("ZMQ: Bound socket_auth\n");
    pthread_create(&worker_auth, NULL, threadAuth, NULL);
    return true;
}
//***** setup ports & call thread *******************//

bool InitZMQServer()
{
    LogPrintf("ZMQ: Starting REQ/REP ZMQ server\n");

    SetupPortAuth();
    SetupPortOpen();
    //poll_setup();

    LogPrintf("ZMQ: done setting up threads\n");

    return true;
}

void InterruptZMQServer()
{
    LogPrint("zmq", "Interrupt REQ/REP ZMQ server\n");
}

void StopZMQServer()
{
    LogPrintf("Stopping REQ/REP ZMQ server\n");
    if (socket_auth)
    {
        zmq_close(socket_auth);
        socket_auth = 0;
    }

    if (context_auth)
    {
        zmq_ctx_destroy(context_auth);
        context_auth = 0;
    }

    if (socket_open)
    {
        zmq_close(socket_open);
        socket_open = 0;
    }

    if (context_open)
    {
        zmq_ctx_destroy(context_open);
        context_open = 0;
    }
    
    //KEEPALIVE=0;
}

/******************* End REQ/REP ZMQ functions ******************************************/
