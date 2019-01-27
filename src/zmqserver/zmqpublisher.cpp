// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "core_io.h"
#include "chain.h"
#include "znode-sync.h"

#include "zmqabstract.h"
#include "zmqpublisher.h"

#include "client-api/wallet.h"
#include "client-api/server.h"
#include "client-api/protocol.h"
#include "univalue.h"

#include <boost/thread/thread.hpp>

extern CWallet *pwalletMain;

static std::multimap<std::string, CZMQAbstractPublisher*> mapPublishers;

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

    // set publishing topic
    SetTopic();

    // set API method string
    SetMethod();

    //set method string in request object
    request.setObject();
    request.push_back(Pair("collection", method));

    // set publish univalue as an object
    publish.setObject();

    // check if authority is being used by any other publisher notifier
    std::multimap<std::string, CZMQAbstractPublisher*>::iterator i = mapPublishers.find(authority);

    // check if authority is being used by other publisher
    if (i==mapPublishers.end())
    {
        psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket)
        {
            zmqError("Failed to create socket");
            return false;
        }
        // TODO latter condition is a short term hack. make into proper inheritence hierarchy
        if(CZMQAbstract::DEV_AUTH && this->topic != "apiStatus"){
            // Set up PUB auth.
            vector<string> keys = readCert(CZMQAbstract::Server);

            string server_secret_key = keys.at(1);

            const int curve_server_enable = 1;
            zmq_setsockopt(psocket, ZMQ_CURVE_SERVER, &curve_server_enable, sizeof(curve_server_enable));
            zmq_setsockopt(psocket, ZMQ_CURVE_SECRETKEY, server_secret_key.c_str(), 40);
        }

        int rc = zmq_bind(psocket, authority.c_str());
        if (rc!=0)
        {
            zmqError("Failed to bind authority");
            zmq_close(psocket);
            return false;
        }

        // register this publisher for the authority, so it can be reused for another publish notifier
        mapPublishers.insert(std::make_pair(authority, this));
        return true;
    }
    else
    {
        LogPrint(NULL, "zmq: Reusing socket for authority %s\n", authority);

        psocket = i->second->psocket;
        mapPublishers.insert(std::make_pair(authority, this));

        return true;
    }
}

void CZMQAbstractPublisher::Shutdown()
{
    if (pcontext)
    {
        assert(psocket);

        int count = mapPublishers.count(authority);

        // remove this notifier from the list of publishers using this authority
        typedef std::multimap<std::string, CZMQAbstractPublisher*>::iterator iterator;
        std::pair<iterator, iterator> iterpair = mapPublishers.equal_range(authority);

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

bool CZMQAbstractPublisher::Execute(){
    APIJSONRequest jreq;
    try {
        jreq.parse(request);

        publish.setObject();
        publish = tableAPI.execute(jreq, true);

        Publish();

    } catch (const UniValue& objError) {
        message = JSONAPIReply(NullUniValue, objError);
        if(!SendMessage()){
            throw JSONAPIError(API_MISC_ERROR, "Could not send msg");
        }
        return false;
    } catch (const std::exception& e) {
        message = JSONAPIReply(NullUniValue, JSONAPIError(API_PARSE_ERROR, e.what()));
        if(!SendMessage()){
            throw JSONAPIError(API_MISC_ERROR, "Could not send error msg");
        }
        return false;
    }
    
    return true;
}

bool CZMQAbstractPublisher::Publish(){
  try {
      // Send reply
      message = JSONAPIReply(publish, NullUniValue);
      if(!SendMessage()){
          throw JSONAPIError(API_MISC_ERROR, "Could not send msg");
      }
      return true;

  } catch (const UniValue& objError) {
      message = JSONAPIReply(NullUniValue, objError);
      if(!SendMessage()){
          throw JSONAPIError(API_MISC_ERROR, "Could not send msg");
      }
      return false;
  } catch (const std::exception& e) {
      message = JSONAPIReply(NullUniValue, JSONAPIError(API_PARSE_ERROR, e.what()));
      if(!SendMessage()){
          throw JSONAPIError(API_MISC_ERROR, "Could not send error msg");
      }
      return false;
  }
}

bool CZMQStatusEvent::NotifyStatus()
{
    Execute();
    return true;
}

bool CZMQAPIStatusEvent::NotifyAPIStatus()
{
    Execute();
    return true;
}


bool CZMQConnectionsEvent::NotifyConnections()
{
    Execute();
    return true;
}

bool CZMQTransactionEvent::NotifyTransaction(const CTransaction &transaction)
{
    CWalletTx wtx(pwalletMain, transaction);
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    isminefilter filter = ISMINE_ALL;
    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    if(listReceived.size() > 0 || listSent.size() > 0){
        UniValue requestData(UniValue::VOBJ);
        string encodedTx;
        try{
            encodedTx = EncodeHexTx(transaction);
        }catch(const std::exception& e){
            throw JSONAPIError(API_DESERIALIZATION_ERROR, "Error parsing or validating structure in raw format"); 
        }
        requestData.push_back(Pair("txRaw",encodedTx));
        request.replace("data", requestData);
        Execute();
    }

    return true;
}

bool CZMQBlockEvent::NotifyBlock(const CBlockIndex *pindex){
    // "block" topic is a special case: if synced, always publish, if not, every 100 blocks (for better sync speed).
    if(topic=="block"){
        if(znodeSync.GetBlockchainSynced() || pindex->nHeight%100==0){
            request.replace("data", pindex->ToJSON());
            Execute(); 
            return true;
        }
    }

    // Otherwise, publish on an update to wallet tx's
    CBlock block;
    if(!ReadBlockFromDisk(block, pindex, Params().GetConsensus())){
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
    {
        const CWalletTx *wtx = pwalletMain->GetWalletTx(tx.GetHash());
        if(wtx){
            request.replace("data", pindex->ToJSON());
            Execute();
            return true;
        }
    }

    return true;
}

bool CZMQZnodeEvent::NotifyZnodeUpdate(CZnode &znode){
    request.replace("data", znode.ToJSON());
    Execute();

    return true;
}

bool CZMQMintStatusEvent::NotifyMintStatusUpdate(std::string update){
    LogPrintf("update in NotifyMintStatusUpdate: %s\n", update);
    UniValue updateObj(UniValue::VOBJ);
    try{
        updateObj.read(update);
    }catch(const std::exception& e){
       throw JSONAPIError(API_PARSE_ERROR, "Could not read mint update"); 
    }
    request.replace("data", updateObj);
    Execute();

    return true;
}

bool CZMQSettingsEvent::NotifySettingsUpdate(std::string update){
    LogPrintf("update in NotifySettingsUpdate: %s\n", update);
    UniValue updateObj(UniValue::VOBJ);
    try{
        updateObj.read(update);
    }catch(const std::exception& e){
       throw JSONAPIError(API_PARSE_ERROR, "Could not read settings update");
    }
    request.replace("data", updateObj);
    Execute();

    return true;
}