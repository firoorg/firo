// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H
#define ZCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H

#include "zmqabstract.h"
#include <boost/thread/thread.hpp>

class CBlockIndex;

class CZMQAbstractReplier : public CZMQAbstract
{  
protected:
    int KEEPALIVE = 1;
    int rc;
    zmq_msg_t request;
    boost::thread* worker;

public:
    // Initialization
    bool Initialize();
    void Shutdown();
    bool Socket();
    bool Bind();

    // Thread handling
    std::string ReadRequest();
    bool Wait();
    bool SendResponse();

    virtual void* Thread() = 0;
    virtual bool Auth() = 0;
};

class CZMQAuthReplier : public CZMQAbstractReplier
{
public:
    bool Auth();
    void* Thread();

};

class CZMQOpenReplier : public CZMQAbstractReplier
{
public:
    bool Auth(){ return true; };
    void* Thread();

};

#endif // ZCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H
