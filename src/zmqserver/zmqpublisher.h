// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQPUBLISHER_H
#define BITCOIN_ZMQ_ZMQPUBLISHER_H

#include "zmqabstract.h"
#include "univalue.h"
#include "znode.h"
#include "client-api/server.h"
#include <boost/thread/thread.hpp>
#include <boost/chrono.hpp>

class CBlockIndex;

class CZMQAbstractPublisher : public CZMQAbstract
{
public:
    bool Initialize();
    void Shutdown();

    bool Execute();
    bool Publish();

    virtual void SetMethod() = 0;
    virtual void SetTopic() = 0;
    
protected:
    std::string method;
    UniValue request;
    UniValue publish;
    boost::thread* worker;

};

/* Special Instance of the CZMQAbstractPublisher class to handle threads. */
class CZMQThreadPublisher : public CZMQAbstractPublisher
{
public:
    static void* Thread(){
        LogPrintf("CZMQAbstractPublisher Thread started.\n");
        const int PUBLISH_TIME_SECS = 1;
        while(true){
            boost::this_thread::sleep_for(boost::chrono::seconds(PUBLISH_TIME_SECS));
            GetMainSignals().NotifyAPIStatus();
        }
    };
};

/* Event classes. Each one is a specific notifier in ValidationInterface. 
   virtual to allow multiple inheritence by topic classes */
class CZMQBlockEvent : virtual public CZMQAbstractPublisher
{
    /* Data related to a new block (updatedblocktip)
    */
public:
    bool NotifyBlock(const CBlockIndex *pindex);
};


class CZMQTransactionEvent : virtual public CZMQAbstractPublisher
{
    /* Data related to a new transaction
    */
public:
    bool NotifyTransaction(const CTransaction &transaction);
};

class CZMQConnectionsEvent : virtual public CZMQAbstractPublisher
{
    /* Updated connection count
    */
public:
    bool NotifyConnections();
};

class CZMQStatusEvent : virtual public CZMQAbstractPublisher
{
    /* Updated blockchain sync status
    */
public:
    bool NotifyStatus();
};

class CZMQAPIStatusEvent : virtual public CZMQAbstractPublisher
{
    /* API Status notification
    */
public:
    bool NotifyAPIStatus();
};

class CZMQSettingsEvent : virtual public CZMQAbstractPublisher
{
     /* Settings updated
    */   
public:
    bool NotifySettingsUpdate(std::string update);
};

class CZMQZnodeEvent : virtual public CZMQAbstractPublisher
{
    /* Data related to an updated Znode
    */
public:
    bool NotifyZnodeUpdate(CZnode &znode);
};

class CZMQMintStatusEvent : virtual public CZMQAbstractPublisher
{
    /* Data related to an updated Znode
    */
public:
    bool NotifyMintStatusUpdate(std::string update);
};

class CZMQBalanceEvent : virtual public CZMQAbstractPublisher
{
    /* Data related to an updated balance
    */
public:
    bool NotifyBalance();
};

/* Topics. inheriting from an event class implies publishing on that event. 
   'method' string is the API method called in client-api/ 
*/
class CZMQBlockDataTopic : public CZMQBlockEvent
{
public:
    void SetTopic(){ topic = "address";}
    void SetMethod(){ method= "block";}
};

class CZMQBlockInfoTopic : public CZMQBlockEvent,
                           public CZMQConnectionsEvent,
                           public CZMQStatusEvent
{
public:
    void SetTopic(){ topic = "block";}
    void SetMethod(){ method= "blockchain";}
};

class CZMQBalanceTopic : public CZMQBlockEvent, 
                         public CZMQTransactionEvent,
                         public CZMQBalanceEvent
                         
{
public:
    void SetTopic(){ topic = "balance";}
    void SetMethod(){ method= "balance";}
};

class CZMQTransactionTopic : public CZMQTransactionEvent
{
public:
    void SetTopic(){ topic = "transaction";}
    void SetMethod(){ method= "transaction";}
};

class CZMQSettingsTopic : public CZMQSettingsEvent
{
public:
    void SetTopic(){ topic = "settings";}
    void SetMethod(){ method= "readSettings";}
};

class CZMQAPIStatusTopic : public CZMQAPIStatusEvent
{
public:
    void SetTopic(){ topic = "apiStatus";}
    void SetMethod(){ method= "apiStatus";}
};

class CZMQZnodeTopic : public CZMQZnodeEvent
{
public:
    void SetTopic(){ topic = "znode";}
    void SetMethod(){ method= "znodeUpdate";}
};

class CZMQMintStatusTopic : public CZMQMintStatusEvent
{
public:
    void SetTopic(){ topic = "mintStatus";}
    void SetMethod(){ method= "mintStatus";}
};

#endif // BITCOIN_ZMQ_ZMQPUBLISHER_H
