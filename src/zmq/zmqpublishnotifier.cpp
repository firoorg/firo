// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "zmqpublishnotifier.h"
#include "main.h"
#include "util.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "base58.h"
#include "client-api/json.hpp"

using json = nlohmann::json;
using namespace std::chrono;

static std::multimap<std::string, CZMQAbstractPublishNotifier*> mapPublishNotifiers;

static const char *MSG_HASHBLOCK = "hashblock";
static const char *MSG_HASHTX    = "hashtx";
static const char *MSG_RAWBLOCK  = "rawblock";
static const char *MSG_RAWTX     = "rawtx";

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

    assert(psocket);

    zmq_msg_t reply;
    int rc = zmq_msg_init_size (&reply, msg.size());
    assert(rc == 0);  
    std::memcpy (zmq_msg_data (&reply), msg.data(), msg.size());
    LogPrintf("ZMQ: Sending reply..\n");
    /* Block until a message is available to be sent from socket */
    rc = zmq_sendmsg (psocket, &reply, 0);
    assert(rc!=-1);

    LogPrintf("ZMQ: Reply sent.\n");
    zmq_msg_close(&reply);

    return true;
}
//*************** START USELESS ****************//
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
//*************** END USELESS ****************//

bool CZMQPublishRawBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    LogPrint(NULL, "zmq: Publish rawblock %s\n", pindex->GetBlockHash().GetHex());

    const Consensus::Params& consensusParams = Params().GetConsensus();
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
    {
        LOCK(cs_main);
        CBlock block;
        if(!ReadBlockFromDisk(block, pindex, consensusParams))
        {
            zmqError("Can't read block from disk");
            return false;
        }

        ss << block;
    }

    return SendMessage(MSG_RAWBLOCK, &(*ss.begin()), ss.size());
}

bool CZMQPublishRawTransactionNotifier::NotifyTransaction(const CTransaction &transaction)
{
    /*
    new address publishing layout:
        {
        "type": "address",
        "id": STRING,
        "transaction": {
            "txid": STRING,
            "timestamp": INT (created here & removed on new blocks)
            "amount": INT,
            "type": type: 'in|out|mint|spend|newcoin'
            "?blockstamp": INT (only added if this tx is part of a block)
        }
    }
    */

    json tx;

    tx["type"] = "address";
    tx["transaction"] = nullptr;
    tx["transaction"]["txid"] = transaction.GetHash().ToString();

    // get time in ms
    milliseconds ms = duration_cast< milliseconds >(
      system_clock::now().time_since_epoch()
    );

    // update 'tx' to include time of creation
    tx["transaction"]["timestamp"] = ms.count();

    // TODO write timestamp back to file.

    // handle tx_outs
    for (int i=0; i < transaction.vout.size(); i++) {
        tx["transaction"]["amount"] = transaction.vout[i].nValue;

        //extract address(es) related to this vout
        CScript scriptPubKey = transaction.vout[i].scriptPubKey;
        vector<string> addresses;   
        vector<CTxDestination> addresses_raw;
        txnouttype type;
        int nRequired;

        ExtractDestinations(scriptPubKey, type, addresses_raw, nRequired);
        BOOST_FOREACH(const CTxDestination& tx_dest, addresses_raw)
            addresses.push_back(CBitcoinAddress(tx_dest).ToString());

            for(int j=0;j<addresses.size();j++){
                 tx["id"] = addresses[j];
                 LogPrintf("ZMQ: tx.dump: %s\n", tx.dump());
                 LogPrintf("ZMQ: address: %s\n", addresses[j]);

                 string address_topic = "address-";

                 tx["transaction"]["type"] = "out";
                 if(transaction.IsCoinBase() && transaction.vout[i].nValue==15 * COIN){
                    tx["transaction"]["type"] = "znode_reward";
                 }
                 else if(transaction.IsCoinBase() && transaction.vout[i].nValue>=28 * COIN){
                    tx["transaction"]["type"] = "mining_reward";
                 }
                 else if(transaction.IsZerocoinMint(transaction)){
                    tx["transaction"]["type"] = "mint";
                 }
                else if(transaction.IsZerocoinSpend()){
                    tx["transaction"]["type"] = "spend";
                 }
                 address_topic.append(addresses[j]).append("-").append(tx.dump());

                 send_message(address_topic);
            }
    } 
    return true;
}

bool CZMQPublishUpdatedBalancesNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    uint256 hashBlock = pindex->GetBlockHash();
    LogPrint(NULL, "zmq: Publish updated balances for block %s\n", hashBlock.GetHex());

    const Consensus::Params& consensusParams = Params().GetConsensus();
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
    {
        LOCK(cs_main);
        CBlock block;
        if(!ReadBlockFromDisk(block, pindex, consensusParams))
        {
            zmqError("Can't read block from disk");
            return false;
        }
        /*
            We want to get the list of addresses where balance is affected.
            for each transaction in the block:
                for each vin of that transaction:
                    for each vout in vin:
                        grab each address.
                for each vout:
                    grab each address.
        */ 

        //list of tx destinations.
        vector<CTxDestination> tx_destinations;

        // temporary list of tx destinations, updated by ExtractDestinations each run -
        // would like to reuse ExtractDestinations rather than modifying/adding a very similar function.
        vector<CTxDestination> temp_tx_destinations;

        // list of bitcoin addresses.
        vector<CBitcoinAddress> bitcoin_addresses;

        // list of index keys (ie. address hashes)
        std::vector<std::pair<uint160, int> > index_keys;

        // list of address indexes (transactions with balance information)
        std::vector<std::pair<CAddressIndexKey, CAmount> > address_indexes;

        // pointer parameters.
        CTransaction tx_vin;
        txnouttype tx_type;
        int nRequired;
        int addr_type;
        uint160 hashBytes;
        CAmount balance;

         BOOST_FOREACH(const CTransaction&tx_base, block.vtx)
         {
            LogPrintf("    zmq: printing transaction hash %s\n", tx_base.GetHash().GetHex());
            //first get addresses associated with vin for tx_base.
            //ignore this part for coinbase txs.         
            for (unsigned int i = 0; i < tx_base.vin.size(); i++) {
                //get next vin for this transaction
                const CTxIn& txin = tx_base.vin[i]; 

                // get tx hash associated with this vin
                uint256 tx_vin_hash = txin.prevout.hash;
                LogPrintf("        zmq: printing vin tx hash %s\n", tx_vin_hash.GetHex());

                //get tx for txid
                GetTransaction(tx_vin_hash, tx_vin, Params().GetConsensus(), hashBlock, true);

                // get all addresses in vout associated with this tx.
                if(!tx_base.IsCoinBase()){
                    for (unsigned int i = 0; i < tx_vin.vout.size(); i++) {
                        // store addresses in temporary data structure
                        ExtractDestinations(tx_vin.vout[i].scriptPubKey, tx_type, temp_tx_destinations, nRequired);
                        // push addresses into master 
                        tx_destinations.insert(tx_destinations.end(),temp_tx_destinations.begin(),temp_tx_destinations.end());
                    }
                }
            }

            // get all vout addresses. 
            for (unsigned int i = 0; i < tx_base.vout.size(); i++) {            
                // store addresses in temporary data structure
                ExtractDestinations(tx_base.vout[i].scriptPubKey, tx_type, temp_tx_destinations, nRequired); 
                // push addresses into master.
                tx_destinations.insert(tx_destinations.end(),temp_tx_destinations.begin(),temp_tx_destinations.end());
            }
         }

        // convert destinations to addresses
        BOOST_FOREACH(const CTxDestination& dest, tx_destinations)
        {
            //create address for destination
            CBitcoinAddress new_addr(dest);
            //push to list of considered addresses
            bitcoin_addresses.push_back(new_addr);
            //get index key for address
            new_addr.GetIndexKey(hashBytes, addr_type);
            //add to vector of index_keys
            index_keys.push_back(std::make_pair(hashBytes, addr_type));
        }

        //remove duplicate indexes and sort for index_keys and addresses.
        sort( index_keys.begin(), index_keys.end() );
        sort( bitcoin_addresses.begin(), bitcoin_addresses.end() );

        index_keys.erase( unique( index_keys.begin(), index_keys.end() ), index_keys.end() );
        bitcoin_addresses.erase( unique( bitcoin_addresses.begin(), bitcoin_addresses.end() ), bitcoin_addresses.end() );

        //get address indexes to calculate new balances.
        for (std::vector<std::pair<uint160, int> >::iterator it = index_keys.begin(); it != index_keys.end(); it++) {
            GetAddressIndex((*it).first, (*it).second, address_indexes);

            //clear stringstream
            ss.clear();

            //total balances for this address.
            for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=address_indexes.begin(); it!=address_indexes.end(); it++) {
                balance += it->second;
            }

            //put balance in stringstream
            ss << balance;

            //get address
            string address = bitcoin_addresses[it - index_keys.begin()].ToString();

            //create topic for zmq msg
            std::string msg = "address-" + address + "-balance";

            LogPrint(NULL, "zmq: Publish updatedbalance for address %s, balance: %s\n", address, to_string(balance));

            //send zmq msg
            SendMessage(msg.c_str(), &(*ss.begin()), ss.size());

            //reset values
            balance = 0;
            address_indexes.clear();
        }
    }
    return true;
}

//get all potential addresses sending to this tx id
// string<vector> getFromAddresses(){

// }

