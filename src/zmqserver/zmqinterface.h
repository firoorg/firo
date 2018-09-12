// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
#define BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H

#include "validationinterface.h"
#include <string>
#include <map>

class CBlockIndex;
class CZMQAbstract;

class CZMQInterface
{
public:
    bool Initialize();
    void Shutdown(); 

protected:
    std::list<CZMQAbstract*> notifiers;
};


class CZMQPublisherInterface : public CValidationInterface, CZMQInterface
{
public:
    virtual ~CZMQPublisherInterface();

    static CZMQPublisherInterface* Create();

protected:
    // CValidationInterface
    void SyncTransaction(const CTransaction& tx, const CBlockIndex *pindex, const CBlock* pblock);
    void UpdatedBlockTip(const CBlockIndex *pindex);
    void NumConnectionsChanged();
    void UpdateSyncStatus();
    void UpdatedZnode(CZnode &znode);

private:
    CZMQPublisherInterface();
};

class CZMQReplierInterface : public CZMQInterface
{
public:
    virtual ~CZMQReplierInterface();

    static CZMQReplierInterface* Create();

private:
    CZMQReplierInterface();
};

#endif // BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
