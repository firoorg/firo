// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H
#define BITCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H

#include "zmqabstract.h"

class CBlockIndex;

class CZMQAbstractReplier : public CZMQAbstract
{
private:
    uint32_t nSequence; //!< upcounting per message sequence number

public:
    bool Initialize();
    void Shutdown();
    bool Socket();
    bool Bind();
    //bool Thread();

    virtual bool Auth() = 0;
};

class CZMQAuthReplier : public CZMQAbstractReplier
{
public:
    bool Auth();

};

class CZMQOpenReplier : public CZMQAbstractReplier
{
public:
    bool Auth(){return true;};

};

#endif // BITCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H
