// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
#define ZCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H

#include "validationinterface.h"
#include <string>
#include <map>
#include <boost/thread/thread.hpp>

class CBlockIndex;
class CZMQAbstract;

class CZMQInterface
{
public:
    bool Initialize();
    void Shutdown(); 

protected:
    std::list<CZMQAbstract*> notifiers;
    boost::thread* worker;
};


class CZMQPublisherInterface : public CValidationInterface, CZMQInterface
{
public:
    CZMQPublisherInterface();
    bool StartWorker();
    virtual ~CZMQPublisherInterface();
    CZMQPublisherInterface* Create();

protected:
    // CValidationInterface
    void WalletTransaction(const CTransaction& tx);
    void UpdatedBlockTip(const CBlockIndex *pindex);
    void NumConnectionsChanged();
    void UpdateSyncStatus();
    void NotifyZnodeList();
    void NotifyAPIStatus();
    void UpdatedZnode(CZnode &znode);
    void UpdatedMintStatus(std::string update);
    void UpdatedSettings(std::string update);
    void UpdatedBalance();
    
};

class CZMQReplierInterface : public CZMQInterface
{
public:
    CZMQReplierInterface();
    virtual ~CZMQReplierInterface();
    CZMQReplierInterface* Create();
};

#endif // ZCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
