// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQPUBLISHER_H
#define BITCOIN_ZMQ_ZMQPUBLISHER_H

#include "zmqabstract.h"
#include "univalue.h"

class CBlockIndex;

class CZMQAbstractPublisher : public CZMQAbstract
{
public:
    //bool writeTimestampToFile(json tx);

    bool processTransaction(const CTransaction &transaction);

    bool Initialize();
    void Shutdown();

    bool Publish();

    virtual void SetMethod() = 0;
    virtual void SetTopic() = 0;

protected:
    std::string method;
    UniValue publish;

};

/* On a new block, publish data on three separate items:
  - new block information
  - general blockchain info
  - balance info
*/
class CZMQBlockPublisher : public CZMQAbstractPublisher
{
public:
    bool NotifyBlock(const CBlockIndex *pindex);
};

class CZMQBlockDataPublisher : public CZMQBlockPublisher
{
public:
    void SetMethod(){ method= "block";};
    void SetTopic(){ topic = "address";};
};

class CZMQBlockInfoPublisher : public CZMQBlockPublisher
{
public:
    void SetMethod(){ method= "blockchain";};
    void SetTopic(){ topic = "block";};
};

class CZMQBalancePublisher : public CZMQBlockPublisher
{
public:
    void SetMethod(){ method= "balance";};
    void SetTopic(){ topic = "balance";};

};

/* publish data related to a new transaction
*/
class CZMQRawTransactionPublisher : public CZMQAbstractPublisher
{
public:
    bool NotifyTransaction(const CTransaction &transaction);
    void SetMethod(){ method= "transaction";};
    void SetTopic(){ topic = "address";};
};

class CZMQSettingsUpdatePublisher : public CZMQAbstractPublisher
{
public:
    bool NotifySettingsUpdate();
    void SetMethod(){ method= "settings";};
    void SetTopic(){ topic = "settings";};
};

#endif // BITCOIN_ZMQ_ZMQPUBLISHER_H
