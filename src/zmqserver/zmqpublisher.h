// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQPUBLISHER_H
#define BITCOIN_ZMQ_ZMQPUBLISHER_H

#include "zmqabstract.h"

class CBlockIndex;

class CZMQAbstractPublisher : public CZMQAbstract
{
private:
    uint32_t nSequence; //!< upcounting per message sequence number

public:

    /* send zmq multipart message
       parts:
          * command
          * data
          * message sequence number
    */
    bool SendTopicMessage(const char *command, const void* data, size_t size);
    bool SendMessage(string msg);

    //bool writeTimestampToFile(json tx);

    bool notifyBalance();

    bool processTransaction(const CTransaction &transaction);

    bool Initialize();
    void Shutdown();
};

class CZMQRawBlockPublisher : public CZMQAbstractPublisher
{
public:
    bool NotifyBlock(const CBlockIndex *pindex);
};

class CZMQRawTransactionPublisher : public CZMQAbstractPublisher
{
public:
    bool NotifyTransaction(const CTransaction &transaction);
};

class CZMQSettingsUpdatePublisher : public CZMQAbstractPublisher
{
public:
    bool NotifySettingsUpdate();
};

#endif // BITCOIN_ZMQ_ZMQPUBLISHER_H
