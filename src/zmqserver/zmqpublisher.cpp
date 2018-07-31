// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "chain.h"
#include "zmqabstract.h"
#include "zmqpublisher.h"
#include "main.h"
#include "util.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "base58.h"
#include "client-api/json.hpp"
#include "zmqserver.h"
#include "znode-sync.h"
#include "net.h"
#include "script/ismine.h"
#include "wallet/wallet.h"
#include "wallet/wallet.cpp"
#include "wallet/rpcwallet.cpp"
#include "client-api/client.h"

#include "chainparamsbase.h"
#include "clientversion.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/filesystem/operations.hpp>
#include <stdio.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <univalue.h>

static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;

using path = boost::filesystem::path;
using json = nlohmann::json;
using namespace std::chrono;

static std::multimap<std::string, CZMQAbstractPublisher*> mapPublishers;
extern CWallet* pwalletMain;

json finalize_json(json request, bool errored){
    json response;
    string key = errored ? "errors" : "data";
    int code = errored ? 400 : 200;
    
    response[key] = request;
    response["meta"]["status"] = code;

    return response;
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
       if (result.isNull()){
           strPrint = "";
       } else if (result.isStr()){
           strPrint = result.get_str();
           response["data"] = strPrint.c_str();
       } else {
           strPrint = result.write(0);
           response["data"] = json::parse(strPrint);
       }

       LogPrintf("ZMQ: result: %s\n", strPrint.c_str());
       response["meta"] = nullptr;
       response["meta"]["status"] = 200;
    }
    
    LogPrintf("ZMQ: returning response.\n");

    return response;
}



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

    LogPrintf("ZMQ: response was a success \n");
    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}


UniValue SetupRPC(std::vector<std::string> args)
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


bool ProcessWalletData(json& result_json, bool isBlock){
   //cycle through result["data"], getting all tx's for one address, and adding balances
    json address_jsons;
    BOOST_FOREACH(json tx_json, result_json["data"]["transactions"]){
        LogPrintf("ZMQ: getting address in req/rep\n");
        string address_str;
        if(tx_json["address"].is_null()){
          address_str = "ZEROCOIN_MINT";
        }else address_str = tx_json["address"];
    
        LogPrintf("ZMQ: address in req/rep: %s\n", address_str);
        string txid = tx_json["txid"];
        LogPrintf("ZMQ: txid in req/rep: %s\n", txid);

        // erase values we don't want to return
        tx_json.erase("account");
        tx_json.erase("vout");
        tx_json.erase("blockindex");
        tx_json.erase("walletconflicts");
        tx_json.erase("bip125-replaceable");
        tx_json.erase("abandoned");
        tx_json.erase("generated");
        tx_json.erase("confirmations");

        if(!tx_json["blockhash"].is_null()){
          string blockhash = tx_json["blockhash"];
          vector<string> rpc_args;
          rpc_args.push_back("getblock");
          rpc_args.push_back(blockhash);
          UniValue rpc_raw = SetupRPC(rpc_args);
          json result_json = response_to_json(rpc_raw);
          tx_json["blockheight"] = result_json["data"]["height"];

        }else tx_json.erase("blockhash");


        if(tx_json["category"]=="generate" || tx_json["category"]=="immature"){
          tx_json["category"] = "mined";
        }

        string category = tx_json["category"];

        LogPrintf("ZMQ: checking fee\n");
        if(!tx_json["fee"].is_null()){
            if(tx_json["fee"]<0){
              float fee = tx_json["fee"];
              tx_json["fee"]=fee * -1;
            }
        }else(tx_json.erase("fee")); 

        // tally up total amount
        float amount;

        amount = tx_json["amount"];
        
        if(address_jsons[address_str]["total"].is_null()){
          address_jsons[address_str]["total"] = nullptr;
        }

        if(category=="send"){
            if(!(address_jsons[address_str]["total"]["sent"].is_null())){ 

              float total_send = address_jsons[address_str]["total"]["sent"];           
              amount += total_send;
            }
            address_jsons[address_str]["total"]["sent"] = amount;
        }
        else{
            if(!(address_jsons[address_str]["total"]["balance"].is_null())){ 
              float total_balance = address_jsons[address_str]["total"]["balance"];           
              amount += total_balance;
            }
            address_jsons[address_str]["total"]["balance"] = amount;
        }

        amount = tx_json["amount"];

        //make negative display values positive
        LogPrintf("ZMQ: checking amount\n");
        if(amount<0){
          tx_json["amount"]=amount * -1;
        }

        amount = tx_json["amount"];

        // add transaction to address field
        address_jsons[address_str]["txids"][txid]["category"][category] = tx_json;
    }

    // make all 'total' values positive
    if(!address_jsons["ZEROCOIN_MINT"].is_null()){
      float balance = address_jsons["ZEROCOIN_MINT"]["total"]["balance"];
      balance *= -1;
      address_jsons["ZEROCOIN_MINT"]["total"]["balance"] = balance;
    }else address_jsons.erase("ZEROCOIN_MINT");
    
    for (json::iterator it = address_jsons.begin(); it != address_jsons.end(); ++it) {
        string address = it.key();
        json value = it.value();
        if(!value["total"]["sent"].is_null()){
            float total = value["total"]["sent"];
            if(total<0){
                total *= -1;
                value["total"]["sent"] = total;
                address_jsons[address] = value;
            }
        }
    }

    result_json["data"] = address_jsons;

    return true;
}


json WalletDataSinceBlock(string block){
    vector<string> rpc_args;
    rpc_args.push_back("listsinceblock");
    rpc_args.push_back(block);

    UniValue rpc_raw = SetupRPC(rpc_args);

    json result_json = response_to_json(rpc_raw);

    ProcessWalletData(result_json, true);

    return result_json;
}

// Internal function to send multipart message
static int zmq_send_multipart(void *sock, const void* data, size_t size, ...)
{
    va_list args;
    va_start(args, size);

    while (1)
    {
        zmq_msg_t msg;

        int rc = zmq_msg_init_size(&msg, size);
        if (rc != 0)
        {
            zmqError("Unable to initialize ZMQ msg");
            return -1;
        }

        void *buf = zmq_msg_data(&msg);
        memcpy(buf, data, size);

        data = va_arg(args, const void*);

        rc = zmq_msg_send(&msg, sock, data ? ZMQ_SNDMORE : 0);
        if (rc == -1)
        {
            zmqError("Unable to send ZMQ msg");
            zmq_msg_close(&msg);
            return -1;
        }

        LogPrintf("ZMQ: message sent.\n");

        zmq_msg_close(&msg);

        if (!data)
            break;

        size = va_arg(args, size_t);
    }
    return 0;
}

bool CZMQAbstractPublisher::Initialize()
{
    LogPrint(NULL, "zmq: Initialize notification interface\n");
    assert(!pcontext);

    pcontext = zmq_init(1);

    if (!pcontext)
    {
        zmqError("Unable to initialize context");
        return false;
    }

    assert(!psocket);

    // check if address is being used by other publish notifier
    std::multimap<std::string, CZMQAbstractPublisher*>::iterator i = mapPublishers.find(address);

    // check if address is being used by other publisher
    if (i==mapPublishers.end())
    {
        psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket)
        {
            zmqError("Failed to create socket");
            return false;
        }

        if(CZMQAbstract::DEV_AUTH){
            // Set up PUB auth.
            vector<string> keys = readCert(CZMQAbstract::Server);

            string server_secret_key = keys.at(1);

            const int curve_server_enable = 1;
            zmq_setsockopt(psocket, ZMQ_CURVE_SERVER, &curve_server_enable, sizeof(curve_server_enable));
            zmq_setsockopt(psocket, ZMQ_CURVE_SECRETKEY, server_secret_key.c_str(), 40);
        }

        int rc = zmq_bind(psocket, address.c_str());
        if (rc!=0)
        {
            zmqError("Failed to bind address");
            zmq_close(psocket);
            return false;
        }

        // register this publisher for the address, so it can be reused for other publish publisher
        mapPublishers.insert(std::make_pair(address, this));
        return true;
    }
    else
    {
        LogPrint(NULL, "zmq: Reusing socket for address %s\n", address);

        psocket = i->second->psocket;
        mapPublishers.insert(std::make_pair(address, this));

        return true;
    }
}

void CZMQAbstractPublisher::Shutdown()
{
    if (pcontext)
    {
        assert(psocket);

        int count = mapPublishers.count(address);

        // remove this notifier from the list of publishers using this address
        typedef std::multimap<std::string, CZMQAbstractPublisher*>::iterator iterator;
        std::pair<iterator, iterator> iterpair = mapPublishers.equal_range(address);

        for (iterator it = iterpair.first; it != iterpair.second; ++it)
        {
            if (it->second==this)
            {
                mapPublishers.erase(it);
                break;
            }
        }
        if (count == 1)
        {
            LogPrint(NULL, "Close socket at authority %s\n", authority);
            int linger = 0;
            zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
            zmq_close(psocket);
        }

        zmq_close(psocket);
        psocket = 0;

        zmq_ctx_destroy(pcontext);
        pcontext = 0;
    }
}

bool CZMQAbstractPublisher::SendTopicMessage(const char *command, const void* data, size_t size)
{
    assert(psocket);

    LogPrintf("zmq: in SendMessage\n");

    /* send three parts, command & data & a LE 4byte sequence number */
    unsigned char msgseq[sizeof(uint32_t)];
    WriteLE32(&msgseq[0], nSequence);
    int rc = zmq_send_multipart(psocket, command, strlen(command), data, size, msgseq, (size_t)sizeof(uint32_t), (void*)0);
    if (rc == -1)
        return false;

    /* increment memory only sequence number after sending */
    nSequence++;

    return true;
}


bool CZMQAbstractPublisher::SendMessage(string msg){

    LogPrintf("ZMQ: sending message %s\n", msg);
    assert(psocket);

    zmq_msg_t reply;
    int rc = zmq_msg_init_size (&reply, msg.size());
    assert(rc == 0);  
    std::memcpy (zmq_msg_data (&reply), msg.data(), msg.size());
    //LogPrintf("ZMQ: Sending reply..\n");
    /* Block until a message is available to be sent from socket */
    rc = zmq_sendmsg (psocket, &reply, 0);
    assert(rc!=-1);

    LogPrintf("ZMQ: message sent.\n");
    zmq_msg_close(&reply);

    return true;
}



bool CZMQAbstractPublisher::notifyBalance(){

    // get confirmed,unconfirmed, locked, private-confirmed, and private-unconfirmed balance.
    vector<string> rpc_args;
    UniValue rpc_raw;
    json result_json;
    float amount;

    //get confirmed
    rpc_args.clear();
    rpc_args.push_back("getbalance");
    rpc_raw = SetupRPC(rpc_args);
    result_json = response_to_json(rpc_raw);
    amount = result_json["data"];
    CAmount xzc_confirmed = amount * COIN;

    //get unconfirmed
    rpc_args.clear();
    rpc_args.push_back("getunconfirmedbalance");
    rpc_raw = SetupRPC(rpc_args);
    result_json = response_to_json(rpc_raw);
    amount = result_json["data"];
    CAmount xzc_unconfirmed = amount * COIN;

    //get locked
    rpc_args.clear();
    rpc_args.push_back("listlockunspentamount");
    rpc_raw = SetupRPC(rpc_args);
    result_json = response_to_json(rpc_raw);
    amount = result_json["data"];
    CAmount xzc_locked = amount * COIN;  

    //get private confirmed
    CAmount zerocoin_all = 0;
    CAmount zerocoin_confirmed = 0;
    pwalletMain->GetAvailableMintCoinBalance(zerocoin_confirmed, true);
    pwalletMain->GetAvailableMintCoinBalance(zerocoin_all, false);

    CAmount zerocoin_unconfirmed = zerocoin_all - zerocoin_confirmed; //the difference of all and confirmed gives unconfirmed

    // We now have all base units, derive return values.
    CAmount total = xzc_confirmed + xzc_unconfirmed + xzc_locked + zerocoin_all;
    CAmount pending = total - xzc_confirmed - zerocoin_confirmed - xzc_locked;
    CAmount available = xzc_confirmed -  xzc_locked;

    json response;

    response["data"]["total"] = nullptr;
    response["data"]["total"]["all"] = total;
    response["data"]["total"]["pending"] = pending;
    response["data"]["total"]["available"] = available;

    response["data"]["xzc"] = nullptr;
    response["data"]["xzc"]["confirmed"] = xzc_confirmed;
    response["data"]["xzc"]["unconfirmed"] = xzc_unconfirmed;
    response["data"]["xzc"]["locked"] = xzc_locked;

    response["data"]["zerocoin"] = nullptr;
    response["data"]["zerocoin"]["confirmed"] = zerocoin_confirmed;
    response["data"]["zerocoin"]["unconfirmed"] = zerocoin_unconfirmed;

    response["meta"]["status"] = 200;


    string topic = "balance";
    string message = response.dump();

    LogPrintf("ZMQ: message: %s\n", message);
    LogPrintf("ZMQ: sending topic message balance\n");
    if(!SendTopicMessage(topic.c_str(), message.c_str(), message.length())){
        LogPrintf("ZMQ: sending topic message balance failed");
        return false;
    }
    LogPrintf("ZMQ: sending topic message balance succeeded\n");
    return true;
}

bool CZMQRawTransactionPublisher::NotifyTransaction(const CTransaction &transaction)
{
    // // get time in ms
    // milliseconds ms = duration_cast< milliseconds >(
    //   system_clock::now().time_since_epoch()
    // );

    if(znodeSync.IsBlockchainSynced()){
        UniValue entry(UniValue::VARR);

        const CWalletTx wtx(pwalletMain, transaction);

        isminefilter filter = ISMINE_SPENDABLE;

        ListTransactions(wtx, "*", 0, true, entry, filter);
        string result_str = entry.write(0);

        json result_json;
        result_json["data"]["transactions"] = json::parse(result_str);

        ProcessWalletData(result_json, false);

        string topic = "address";
        string message = result_json.dump();

        if(!SendTopicMessage(topic.c_str(), message.c_str(), message.length())){
            return false;
        }
    }
    
    return true;
}

bool CZMQRawBlockPublisher::NotifyBlock(const CBlockIndex *pindex)
{
    LogPrintf("API: In notifyblock\n");
    //publish block related info every 10 blocks.
    int currentHeight = pindex->nHeight;
    string topic;
    string message;
    LogPrintf("ZMQ: in notifyblock. currentHeight: %s\n", to_string(currentHeight));
    bool syncing = (currentHeight % 10==0 && currentHeight >=10);
    string prevblockhash;
    if(syncing || znodeSync.IsBlockchainSynced()){
        // if blockchain synced - get every block. if not get 10 previous blocks every 10
        if(znodeSync.IsBlockchainSynced()){
            prevblockhash = pindex->GetBlockHash().ToString();
        }else {
            LogPrintf("zmq: currentheight: %s\n", to_string(currentHeight));
            prevblockhash = chainActive[currentHeight - 10]->GetBlockHash().ToString();
            LogPrintf("zmq: prevblockhash: %s\n", prevblockhash);
        }

        json result_json;
        result_json = WalletDataSinceBlock(prevblockhash);

        topic = "address";
        message = result_json.dump();
        if(!SendTopicMessage(topic.c_str(), message.c_str(), message.length())){
            return false;
        }
    }

    //publish Blockchain related info.
    json block_json;
    block_json["type"] = "full";
    block_json["status"] = nullptr;

    block_json["status"]["IsBlockchainSynced"] = znodeSync.IsBlockchainSynced();
    block_json["status"]["IsZnodeListSynced"] = znodeSync.IsZnodeListSynced();
    block_json["status"]["IsWinnersListSynced"] = znodeSync.IsWinnersListSynced();
    block_json["status"]["IsSynced"] = znodeSync.IsSynced();
    block_json["status"]["IsFailed"] = znodeSync.IsFailed();

    block_json["testnet"] = Params().TestnetToBeDeprecatedFieldRPC();

    block_json["connections"] = (int)vNodes.size();

    block_json["currentBlock"] = nullptr;
    block_json["currentBlock"]["height"] = pindex->nHeight;
    block_json["currentBlock"]["timestamp"] = pindex->nTime;

    json response = finalize_json(block_json, false);

    topic = "block";
    message = response.dump();
    if(!SendTopicMessage(topic.c_str(), message.c_str(), message.length())){
        return false;
    }

    //Publish balance info.
    if(!notifyBalance()){
        return false;
    }

    return true;
}

// bool CZMQAbstractPublisher::writeTimestampToFile(json tx){
//     //get payment request data
//     path persistent_pr = GetDataDir(true) / "persistent" / "tx-timestamp.json";

//     // get raw string
//     std::ifstream persistent_pr_in(persistent_pr.string());

//     // convert to JSON
//     json persistent_pr_json;
//     persistent_pr_in >> persistent_pr_json;

//     // get "data" object from JSON
//     json data_json = persistent_pr_json["data"];

//     string txid = tx["transaction"]["txid"];
//     int timestamp = tx["transaction"]["timestamp"];

//     data_json[txid] = timestamp;

//     // write request back to JSON
//     persistent_pr_json["data"] = data_json;
        
//     // write back to file.
//     std::ofstream persistent_pr_out(persistent_pr.string());
//     persistent_pr_out << std::setw(4) << persistent_pr_json << std::endl;

//     return true;
// }