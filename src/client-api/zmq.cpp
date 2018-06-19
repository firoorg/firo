#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "json.hpp"
#include "client-api/zmq.h"
#include "client-api/server.h"
#include "zmq/zmqpublishnotifier.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "clientversion.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"
#include "utilstrencodings.h"
#include <chrono>

#include <boost/filesystem/operations.hpp>
#include <stdio.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <univalue.h>

#include <iostream>
#include <sstream>
//import rpc methods. or use the table?

using json = nlohmann::json;
using namespace std::chrono;


static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;

/** Reply structure for request_done to fill in */
/*************** Start RPC setup functions *****************************************/
struct HTTPReply
{
    int status; 
    std::string body;
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int> > members;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
};

static CRPCConvertTable rpcCvtTable;

/** Convert strings to command-specific RPC representation */
UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting, but
         * I'm not sure how to find out which one. We also don't really care.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

UniValue CallRPC(const string& strMethod, const UniValue& params)
{
    std::string host = GetArg("-rpcconnect", DEFAULT_RPCCONNECT);
    int port = GetArg("-rpcport", BaseParams().RPCPort());

    // Create event base
    struct event_base *base = event_base_new(); // TODO RAII
    if (!base)
        throw runtime_error("cannot create event_base");

    // Synchronously look up hostname
    struct evhttp_connection *evcon = evhttp_connection_base_new(base, NULL, host.c_str(), port); // TODO RAII
    if (evcon == NULL)
        throw runtime_error("create connection failed");
    evhttp_connection_set_timeout(evcon, GetArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));

    HTTPReply response;
    struct evhttp_request *req = evhttp_request_new(http_request_done, (void*)&response); // TODO RAII
    if (req == NULL)
        throw runtime_error("create http request failed");

    // Get credentials
    std::string strRPCUserColonPass;
    if (mapArgs["-rpcpassword"] == "") {
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetAuthCookie(&strRPCUserColonPass)) {
            throw runtime_error(strprintf(
                _("Could not locate RPC credentials. No authentication cookie could be found, and no rpcpassword is set in the configuration file (%s)"),
                    GetConfigFile().string().c_str()));

        }
    } else {
        strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    }

    struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req);
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequest(strMethod, params, 1);
    struct evbuffer * output_buffer = evhttp_request_get_output_buffer(req);
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/");
    if (r != 0) {
        evhttp_connection_free(evcon);
        event_base_free(base);
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base);
    evhttp_connection_free(evcon);
    event_base_free(base);

    if (response.status == 0)
        throw CConnectionFailed("couldn't connect to server");
    else if (response.status == HTTP_UNAUTHORIZED)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}


UniValue setupRPC(std::vector<std::string> args)
{
   string strPrint;
   int nRet = 0;
   UniValue reply;
   json j;
   try {
       std::string strMethod = args[0];

       UniValue params = RPCConvertValues(strMethod, std::vector<std::string>(args.begin()+1, args.end()));

       // Execute and handle connection failures with -rpcwait
       const bool fWait = GetBoolArg("-rpcwait", false);
       do {
           try {
               reply = CallRPC(strMethod, params);
               // Connection succeeded, no need to retry.
               break;
           }
           catch (const CConnectionFailed&) {
               if (fWait)
                   MilliSleep(1000);
               else
                   throw;
           }
       } while (fWait);
   }
   catch (const boost::thread_interrupted&) {
       throw;
   }
   catch (const std::exception& e) {
       strPrint = string("error: ") + e.what();
       nRet = EXIT_FAILURE;
   }
   catch (...) {
       PrintExceptionContinue(NULL, "CommandLineRPC()");
       throw;
   }

   return reply;
}
/*************** End RPC setup functions **********************************************/



/******************* Start parsing functions ******************************************/

std::vector<std::string> parse_request(string request_str){
    auto request_json = json::parse(request_str);

    // if data is an object (ie. it is a JSON argument itself):
    //    take 'data' as a single arg into the vector, and pass along with command name.
    // if data is an array of arguments, cycle through 'data' args and store in vector.

    std::vector<std::string> request_vector;
    request_vector.push_back(request_json["type"]);

    if(request_json["data"].is_object()){
      std::string data = request_json["data"].dump();
      request_vector.push_back(data.c_str());            
    }
    else {
      for (auto& element : request_json["data"]) {
        request_vector.push_back(element);            
      }
    }

    return request_vector;
}

json response_to_json(UniValue reply){
    // Parse reply
    LogPrintf("ZMQ: in response_to_json.\n");
    json response;
    string strPrint;
    int nRet = 0;
    const UniValue& result = find_value(reply, "result");
    const UniValue& error  = find_value(reply, "error");


    if (!error.isNull()) {
       // Error state.
       response["errors"] = nullptr;
       response["errors"]["meta"] = 400;
       LogPrintf("ZMQ: errored.\n");
       int code = error["code"].get_int();
       strPrint = "error: " + error.write();
       nRet = abs(code);
       if (error.isObject())
       {
           UniValue errMsg  = find_value(error, "message");
           UniValue errCode = find_value(error, "code");
           response["errors"]["message"] = errMsg.getValStr();
           response["errors"]["code"] = errCode.getValStr();
           strPrint = errCode.isNull() ? "" : "error code: "+errCode.getValStr()+"\n";

           if (errMsg.isStr())
               strPrint += "error message:\n"+errMsg.get_str();
       }
    } else {
       // Result
       if (result.isNull())
           strPrint = "";
       else if (result.isStr())
           strPrint = result.get_str();
       else
           strPrint = result.write(2);
       LogPrintf("ZMQ: result: %s\n", strPrint.c_str());
       response["data"] = strPrint.c_str();
       response["meta"] = nullptr;
       response["meta"]["meta"] = 200;
    }
    
    LogPrintf("ZMQ: returning response.\n");

    return response;
}

/******************* End parsing functions ******************************************/



/*************** Start API function definitions ***************************************/

json payment_request(json request){

    //get payment request data
    boost::filesystem::path persistent_pr = GetDataDir(false) / (Params().NetworkIDString()==CBaseChainParams::TESTNET ? "testnet3" : "") / "persistent" / "payment_request.json";

    // get raw string
    std::ifstream persistent_pr_in(persistent_pr.string());

    // convert to JSON
    json persistent_pr_json;
    persistent_pr_in >> persistent_pr_json;

    // get "data" object from JSON
    json data_json = persistent_pr_json["data"];

    //misc values for use
    json reply;
    string address;

    LogPrintf("ZMQ: got to before request check");

    if(request["type"]=="create"){

        vector<string> rpc_vector;
        // First get new address for the payment request
        rpc_vector.push_back("getnewaddress"); 

        // Execute getnewaddress command
        UniValue rpc_raw = setupRPC(rpc_vector);

        // extract address
        json rpc_json = response_to_json(rpc_raw);
        address = rpc_json["data"];

        LogPrintf("ZMQ: got to before time entry");

        // get time in ms
        milliseconds ms = duration_cast< milliseconds >(
          system_clock::now().time_since_epoch()
        );

        // update 'request' to include time of creation
        request["data"]["created_at"] = ms.count();

        //update data to include `request`
        data_json[address] = request["data"];

        //set up reply value
        reply["data"] = data_json[address];
        // add address inside data object (only for reply - values are indexed by address in storage)
        reply["data"]["address"] = address;
        reply["meta"] = nullptr;
        reply["meta"]["status"] = 200;
    }

    if(request["type"]=="delete"){
        // remove payment request
        address = request["data"]["id"];

        // ensure address entry exists. only continue should this exist.
        if (data_json.find(address) == data_json.end()) {
          // TODO handle return value.
          reply["errors"] = nullptr;
          reply["errors"]["meta"] = 400;
          reply["errors"]["message"] = "The payment request ID does not exist.";
          return reply;
        }

        data_json.erase(address);
        
        //set up reply value
        json _delete;
        reply["data"] = _delete;
        reply["meta"] = nullptr;
        reply["meta"]["status"] = 200;
    }

    if(request["type"]=="update"){
        address = request["data"]["id"];

        // ensure address entry exists. only continue should this exist.
        if (data_json.find(address) == data_json.end()) {
          // TODO handle return value.
          reply["errors"] = nullptr;
          reply["errors"]["message"] = "The payment request ID does not exist.";
          reply["meta"] = nullptr;
          reply["meta"]["status"] = 400;
          return reply;
        }

        // remove address from 'request' as we do not want to add this field to the data payload.
        request["data"].erase("id");

        // cycle through new values and replace
        for (json::iterator it = request["data"].begin(); it != request["data"].end(); ++it) {
            data_json[address][it.key()] = it.value();
        }

        //set up reply value
        reply["data"] = data_json[address];
        // add address inside data object (only for reply - values are indexed by address in storage)
        reply["data"]["address"] = address;
        reply["meta"] = nullptr;
        reply["meta"]["status"] = 200;
    }

    if(request["type"]=="initial"){
      //TODO status codes
      reply["data"] = data_json;

      // special iterator member functions for objects
      for (json::iterator it = reply["data"].begin(); it != reply["data"].end(); ++it) {
        string address = it.key();
        reply["data"][address]["id"] = address;
      }

      reply["meta"] = nullptr;
      reply["meta"]["status"] = 200;
    }
      
    // write request back to JSON
    persistent_pr_json["data"] = data_json;
        
    // write back to file.
    std::ofstream persistent_pr_out(persistent_pr.string());
    persistent_pr_out << std::setw(4) << persistent_pr_json << std::endl;

    // Return reply.
    return reply;

}

/*************** End API function definitions *****************************************/

/******************* Start REQ/REP ZMQ functions ******************************************/
void *zmqpcontext;
void *zmqpsocket;

void zmqError(const char *str)
{
    LogPrint(NULL, "zmq: Error: %s, errno=%s\n", str, zmq_strerror(errno));
}

pthread_mutex_t mxq;
int needStopREQREPZMQ(){
    switch(pthread_mutex_trylock(&mxq)) {
    case 0: /* if we got the lock, unlock and return 1 (true) */
        pthread_mutex_unlock(&mxq);
        return 1;
    case EBUSY: /* return 0 (false) if the mutex was locked */
        return 0;
    }
    return 1;
}

// arg[0] is the broker
static void* REQREP_ZMQ(void *arg)
{
    while (1) {
        // 1. get request message
        // 2. do something in tableZMQ
        // 3. reply result

        /* Create an empty ØMQ message to hold the message part. */
        /* message assumed to contain an RPC command to be executed with args */
        zmq_msg_t request;
        int rc = zmq_msg_init (&request);
        assert (rc == 0);
        /* Block until a message is available to be received from socket */
        rc = zmq_recvmsg (zmqpsocket, &request, 0);
        if(rc==-1) return NULL;

        char* request_chars = (char*) malloc (rc + 1);

        LogPrintf("ZMQ: Received message request.\n");

        /* convert request to (char*) */
        memcpy (request_chars, zmq_msg_data (&request), rc);
        zmq_msg_close(&request);
        request_chars[rc]=0;

        /* char* to string */
        string request_str(request_chars);

        LogPrintf("ZMQ: 444.\n");

        /* finally, as JSON */
        json request_json = json::parse(request_str);
        
        // variables for the arguments passed in any RPC calls
        UniValue rpc_raw;
        json rpc_json;
        std::vector<std::string> rpc_vector;

        LogPrintf("ZMQ: 454.\n");  
        LogPrintf("ZMQ: request_json string:%s\n", request_json.dump());

        // TODO better scheme for this as more requests added (see RPCTable)
        if(request_json["collection"]=="payment-request"){
            rpc_json = payment_request(request_json);
        }

        /* TODO- generally, what to return for API requests.
           in create-payment-request, client only needs a status and an address back, so don't need to modify JSON call.
           this will likely be different for different calls. 
        */

        /* Send reply */
        string response_str = rpc_json.dump();
        zmq_msg_t reply;
        rc = zmq_msg_init_size (&reply, response_str.size());
        assert(rc == 0);  
        std::memcpy (zmq_msg_data (&reply), response_str.data(), response_str.size());
        LogPrintf("ZMQ: Sending reply..\n");
        /* Block until a message is available to be sent from socket */
        rc = zmq_sendmsg (zmqpsocket, &reply, 0);
        assert(rc!=-1);

        LogPrintf("ZMQ: Reply sent.\n");
        zmq_msg_close(&reply);

    }

    return (void*)true;
}

bool StartREQREPZMQ()
{
    LogPrintf("ZMQ: Starting REQ/REP ZMQ server\n");
    // TODO authentication

    zmqpcontext = zmq_ctx_new();

    zmqpsocket = zmq_socket(zmqpcontext,ZMQ_REP);
    if(!zmqpsocket){
        LogPrintf("ZMQ: Failed to create socket\n");
        return false;
    }

    // Get network port.
    string port;
    if(Params().NetworkIDString()==CBaseChainParams::MAIN){
      port = "15557";
    }
    else if(Params().NetworkIDString()==CBaseChainParams::TESTNET){
      port = "15558";
    }
    //should fail otherwise 

    LogPrintf("ZMQ: port = %s\n", port);

    string tcp = "tcp://*:";

    int rc = zmq_bind(zmqpsocket, tcp.append(port).c_str());
    //int rc = zmq_bind(zmqpsocket, "tcp://*:5558");
    if (rc == -1)
    {
        LogPrintf("ZMQ: Unable to send ZMQ msg\n");
        return false;
    }
    LogPrintf("ZMQ: Bound socket\n");
    //pthread_mutex_init(&mxq,NULL);
    //pthread_mutex_lock(&mxq);
    //create worker & run a thread 
    pthread_t worker;
    pthread_create(&worker,NULL, REQREP_ZMQ, NULL);
    return true;
}

void InterruptREQREPZMQ()
{
    LogPrint("zmq", "Interrupt REQ/REP ZMQ server\n");
}

void StopREQREPZMQ()
{
    LogPrint("zmq", "Stopping REQ/REP ZMQ server\n");
    pthread_mutex_unlock(&mxq);
}

/******************* End REQ/REP ZMQ functions ******************************************/
