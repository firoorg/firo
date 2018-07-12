// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "chain.h"
#include "zmqpublishnotifier.h"
#include "main.h"
#include "util.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "base58.h"
#include "client-api/json.hpp"
#include "client-api/zmq.h"
#include "znode-sync.h"
#include "net.h"
#include "client-api/zmq.h"

using path = boost::filesystem::path;
using json = nlohmann::json;
using namespace std::chrono;

static std::multimap<std::string, CZMQAbstractPublishNotifier*> mapPublishNotifiers;

static const char *MSG_HASHBLOCK = "hashblock";
static const char *MSG_HASHTX    = "hashtx";
static const char *MSG_RAWBLOCK  = "rawblock";
static const char *MSG_RAWTX     = "rawtx";

static const int ISBLOCKTX   = 0;
static const int BLOCKHEIGHT = 1;
static const int BLOCKTIME   = 2;

void *psocket;

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

bool CZMQAbstractPublishNotifier::Initialize(void *pcontext)
{
    assert(!psocket);

    // check if address is being used by other publish notifier
    std::multimap<std::string, CZMQAbstractPublishNotifier*>::iterator i = mapPublishNotifiers.find(address);

    if (i==mapPublishNotifiers.end())
    {
        psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket)
        {
            zmqError("Failed to create socket");
            return false;
        }

        if(DEV_AUTH){
            // Set up PUB auth.
            vector<string> keys = read_cert("server");

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

        // register this notifier for the address, so it can be reused for other publish notifier
        mapPublishNotifiers.insert(std::make_pair(address, this));
        return true;
    }
    else
    {
        LogPrint(NULL, "zmq: Reusing socket for address %s\n", address);

        psocket = i->second->psocket;
        mapPublishNotifiers.insert(std::make_pair(address, this));

        return true;
    }
}

void CZMQAbstractPublishNotifier::Shutdown()
{
    assert(psocket);

    int count = mapPublishNotifiers.count(address);

    // remove this notifier from the list of publishers using this address
    typedef std::multimap<std::string, CZMQAbstractPublishNotifier*>::iterator iterator;
    std::pair<iterator, iterator> iterpair = mapPublishNotifiers.equal_range(address);

    for (iterator it = iterpair.first; it != iterpair.second; ++it)
    {
        if (it->second==this)
        {
            mapPublishNotifiers.erase(it);
            break;
        }
    }

    if (count == 1)
    {
        LogPrint(NULL, "Close socket at address %s\n", address);
        int linger = 0;
        zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(psocket);
    }

    psocket = 0;
}

bool CZMQAbstractPublishNotifier::SendMessage(const char *command, const void* data, size_t size)
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


bool CZMQAbstractPublishNotifier::send_message(string msg){

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



/***************** not used *******************/
bool CZMQPublishHashBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    uint256 hash = pindex->GetBlockHash();
    LogPrint(NULL, "zmq: Publish hashblock %s\n", hash.GetHex());
    char data[32];
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hash.begin()[i];
    return SendMessage(MSG_HASHBLOCK, data, 32);
}

bool CZMQPublishHashTransactionNotifier::NotifyTransaction(const CTransaction &transaction)
{
    uint256 hash = transaction.GetHash();
    LogPrint(NULL, "zmq: Publish hashtx %s\n", hash.GetHex());
    char data[32];
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hash.begin()[i];
    return SendMessage(MSG_HASHTX, data, 32);
}
/***************** not used *******************/



bool CZMQPublishRawTransactionNotifier::NotifyTransaction(const CTransaction &transaction)
{
    /*
    address publishing layout for new tx's:
        {
            "type": "address",
            "id": STRING,
            "transaction": {
                "txid": STRING,
                "timestamp": INT (created here & changed to block timestamp with 6 confs)
                "amount": INT
                "type": type: 'in|out|mint|spend|mining|znode'
            }
        }
    */
    LogPrintf("ZMQ: in NotifyTransaction\n");
    if(znodeSync.IsBlockchainSynced()){
        vector<int> blockParams;
        //blockParams[ISBLOCKTX] is false here
        blockParams.push_back(0);
        processTransaction(transaction, blockParams);
        LogPrintf("ZMQ: processed Transaction\n");
    }
    vector<string> test_args;
    
    return true;
}

bool CZMQPublishRawBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    //publish block related info every 10 blocks.
    int currentHeight = pindex->nHeight;
    string topic;
    LogPrintf("ZMQ: in notifyblock. currentHeight: %s\n", to_string(currentHeight));
    if(currentHeight % 10==0 && currentHeight >=10){
        string prevblockhash = chainActive[currentHeight-10]->GetBlockHash().ToString();
        LogPrintf("ZMQ: prevblockhash: %s\n", prevblockhash);

        json result_json;
        result_json = WalletDataSinceBlock(prevblockhash);

        topic = "address-";
        topic.append(result_json.dump());
        send_message(topic);
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

    topic = "block-";
    topic.append(block_json.dump());
    send_message(topic);

    return true;
}

bool CZMQAbstractPublishNotifier::writeTimestampToFile(json tx){
    //get payment request data
    path persistent_pr = GetDataDir(true) / "persistent" / "tx-timestamp.json";

    // get raw string
    std::ifstream persistent_pr_in(persistent_pr.string());

    // convert to JSON
    json persistent_pr_json;
    persistent_pr_in >> persistent_pr_json;

    // get "data" object from JSON
    json data_json = persistent_pr_json["data"];

    string txid = tx["transaction"]["txid"];
    int timestamp = tx["transaction"]["timestamp"];

    data_json[txid] = timestamp;

    // write request back to JSON
    persistent_pr_json["data"] = data_json;
        
    // write back to file.
    std::ofstream persistent_pr_out(persistent_pr.string());
    persistent_pr_out << std::setw(4) << persistent_pr_json << std::endl;

    return true;
}

bool CZMQAbstractPublishNotifier::processTransaction(const CTransaction &transaction, vector<int> blockvals){
    // if blockvals[ISBLOCKTX] =1, this transaction is part of a block.
    json tx_json_in;
    json tx_json_outs;

    // get time in ms
    milliseconds ms = duration_cast< milliseconds >(
      system_clock::now().time_since_epoch()
    );
    
    // first get addresses of inputs

    // if(!transaction.IsCoinBase()){
    //     for (int i=0; i < transaction.vin.size(); i++) {
    //         CTransaction txPrev;
    //         uint256 hashBlock;
    //         // get the vin's previous transaction 
    //         GetTransaction(transaction.vin[i].prevout.hash, txPrev, Params().GetConsensus(), hashBlock, true);  
    //         CTxDestination source;
    //         // extract the destination of the previous transaction's vout[n]
    //         CTxOut prevout = txPrev.vout[transaction.vin[i].prevout.n];
    //         CAmount amount  = prevout.nValue;
    //         if (ExtractDestination(prevout.scriptPubKey, source))  
    //         {
    //             CBitcoinAddress addressSource(source);              // convert this to an address
    //             string btc_address = addressSource.ToString();
    //             tx_json_outs[btc_address]["id"] = btc_address;
    //             tx_json_outs[btc_address]["type"] = "address";
    //             tx_json_outs[btc_address]["transaction"] = nullptr;
    //             tx_json_outs[btc_address]["transaction"]["txid"] = transaction.GetHash().ToString();
    //             tx_json_outs[btc_address]["transaction"]["type"] = "out";

    //             if(tx_json_outs[btc_address]["transaction"]["amount"].is_null()){
    //                tx_json_outs[btc_address]["transaction"]["amount"] = amount;
    //             }
    //             else{
    //                tx_json_outs[btc_address]["transaction"]["amount"] += amount;
    //             }

    //             if (blockvals[ISBLOCKTX]==1){
    //                 tx_json_outs[btc_address]["transaction"]["timestamp"] = blockvals[BLOCKTIME];
    //                 tx_json_outs[btc_address]["transaction"]["blockstamp"] = blockvals[BLOCKHEIGHT];
    //             }else{
    //                 tx_json_outs[btc_address]["transaction"]["timestamp"] = ms.count();
    //             }  
    //         }
    //     }
        
        // // send all the out address values
        // BOOST_FOREACH(json tx_json, tx_json_outs){
        //     string address_topic = "address-";
        //     string address = tx_json["id"];
        //     address_topic.append(address).append("-").append(tx_json.dump());
        //     send_message(address_topic);
        // }
    // }

    tx_json_in["type"] = "address";
    tx_json_in["transaction"] = nullptr;
    tx_json_in["transaction"]["txid"] = transaction.GetHash().ToString();
    tx_json_in["transaction"]["timestamp"] = ms.count();


    if (blockvals[ISBLOCKTX]==1){
        tx_json_in["transaction"]["timestamp"] = blockvals[BLOCKTIME];
        tx_json_in["transaction"]["blockstamp"] = blockvals[BLOCKHEIGHT];
    }else{
        tx_json_in["transaction"]["timestamp"] = ms.count();
    } 

    //  write timestamp to file in the case that this is not a block tx.
    if(blockvals[ISBLOCKTX]==0) writeTimestampToFile(tx_json_in);
        

    // handle tx_outs
    for (unsigned long i=0; i < transaction.vout.size(); i++) {
        tx_json_in["transaction"]["amount"] = transaction.vout[i].nValue;

        //extract address(es) related to this vout
        CScript scriptPubKey = transaction.vout[i].scriptPubKey;
        vector<string> addresses;   
        vector<CTxDestination> addresses_raw;
        txnouttype type;
        int nRequired;

        ExtractDestinations(scriptPubKey, type, addresses_raw, nRequired);
        BOOST_FOREACH(const CTxDestination& tx_dest, addresses_raw)
            addresses.push_back(CBitcoinAddress(tx_dest).ToString());

        for(unsigned long j=0;j<addresses.size();j++){
             tx_json_in["id"] = addresses[j];
             // LogPrintf("ZMQ: tx.dump: %s\n", tx_json_in.dump());
             // LogPrintf("ZMQ: address: %s\n", addresses[j]);
             // LogPrintf("ZMQ: isBlockTX: %s\n", to_string(blockvals[ISBLOCKTX]));

             string address_topic = "address-";

             tx_json_in["transaction"]["type"] = "in";
             if(transaction.IsCoinBase() && transaction.vout[i].nValue==15 * COIN){
                tx_json_in["transaction"]["type"] = "znode";
             }
             else if(transaction.IsCoinBase() && transaction.vout[i].nValue>=28 * COIN){
                tx_json_in["transaction"]["type"] = "mining";
             }
             else if(transaction.IsZerocoinMint()){
                tx_json_in["transaction"]["type"] = "mint";
             }
            else if(transaction.IsZerocoinSpend()){
                tx_json_in["transaction"]["type"] = "spend";
             }
             address_topic.append(addresses[j]).append("-").append(tx_json_in.dump());

             send_message(address_topic);
        }
    } 
    return true;

}