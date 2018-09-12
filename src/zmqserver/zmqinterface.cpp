// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zmqinterface.h"
#include "zmqpublisher.h"
#include "zmqreplier.h"

#include "version.h"
#include "chainparamsbase.h"
#include "main.h"
#include "streams.h"
#include "util.h"

void zmqError(const char *str)
{
    LogPrint(NULL, "zmq: Error: %s, errno=%s\n", str, zmq_strerror(errno));
}

// Called at startup to conditionally set up ZMQ socket(s)
bool CZMQInterface::Initialize()
{
    std::list<CZMQAbstract*>::iterator i=notifiers.begin();
    for (; i!=notifiers.end(); ++i)
    {
        CZMQAbstract *notifier = *i;
        if (notifier->Initialize())
        {
            LogPrint(NULL, "  Notifier %s ready (address = %s)\n", notifier->GetType(), notifier->GetAuthority());
        }
        else
        {
            LogPrint(NULL, "  Notifier %s failed (address = %s)\n", notifier->GetType(), notifier->GetAuthority());
            return false;
        }
    }

    if (i!=notifiers.end())
    {
        return false;
    }

    return true;
}

// Called during shutdown sequence
void CZMQInterface::Shutdown()
{
    for (std::list<CZMQAbstract*>::iterator i=notifiers.begin(); i!=notifiers.end(); ++i)
    {
        CZMQAbstract *notifier = *i;
        LogPrint(NULL, "   Shutdown notifier %s at %s\n", notifier->GetType(), notifier->GetAuthority());
        notifier->Shutdown();
    }
}

CZMQReplierInterface::CZMQReplierInterface()
{
}

CZMQReplierInterface::~CZMQReplierInterface()
{
    Shutdown();

    for (std::list<CZMQAbstract*>::iterator i=notifiers.begin(); i!=notifiers.end(); ++i)
    {
        delete *i;
    }
}

CZMQReplierInterface* CZMQReplierInterface::Create()
{
    CZMQReplierInterface* replierInterface = NULL;
    std::map<std::string, CZMQFactory> factories;
    std::list<CZMQAbstract*> notifiers;

    factories["auth"] = CZMQAbstract::Create<CZMQAuthReplier>;
    factories["open"] = CZMQAbstract::Create<CZMQOpenReplier>;

    for (std::map<std::string, CZMQFactory>::const_iterator i=factories.begin(); i!=factories.end(); ++i)
    {
        string type = i->first;
        string address = BaseParams().APIAddr();
        string port = type=="auth" ? to_string(BaseParams().APIAuthREPPort()) : 
                                     to_string(BaseParams().APIOpenREPPort());

        CZMQFactory factory = factories[type];
        CZMQAbstract *notifier = factory();
        notifier->SetType("REP" + type);
        notifier->SetAddress(address);
        notifier->SetPort(port);
        notifier->SetAuthority(address + port);
        notifiers.push_back(notifier);
    }


    replierInterface = new CZMQReplierInterface();
    replierInterface->notifiers = notifiers;

    if (!replierInterface->Initialize())
    {
        delete replierInterface;
        replierInterface = NULL;
    }
    

    LogPrintf("returning CZMQReplierInterface\n");
    return replierInterface;
}


CZMQPublisherInterface::CZMQPublisherInterface()
{
}

CZMQPublisherInterface::~CZMQPublisherInterface()
{
    Shutdown();

    for (std::list<CZMQAbstract*>::iterator i=notifiers.begin(); i!=notifiers.end(); ++i)
    {
        delete *i;
    }
}

CZMQPublisherInterface* CZMQPublisherInterface::Create()
{
    LogPrintf("in CreateWithArguments..\n");
    CZMQPublisherInterface* notificationInterface = NULL;
    std::map<std::string, CZMQFactory> factories;
    std::list<CZMQAbstract*> notifiers;

    factories["pubblock"] = CZMQAbstract::Create<CZMQBlockDataTopic>;
    factories["pubrawtx"] = CZMQAbstract::Create<CZMQTransactionTopic>;
    factories["pubblockinfo"] = CZMQAbstract::Create<CZMQBlockInfoTopic>;
    factories["pubbalance"] = CZMQAbstract::Create<CZMQBalanceTopic>;
    factories["pubznodeupdate"] = CZMQAbstract::Create<CZMQZnodeTopic>;
    
    std::string address = BaseParams().APIAddr() + to_string(BaseParams().APIPUBPort());

    for (std::map<string, CZMQFactory>::const_iterator i=factories.begin(); i!=factories.end(); ++i)
    {
        CZMQFactory factory = factories[i->first];
        CZMQAbstract *notifier = factory();
        notifier->SetType("zmq" + i->first);
        notifier->SetAddress(address);
        notifiers.push_back(notifier);
    }

    notificationInterface = new CZMQPublisherInterface();
    notificationInterface->notifiers = notifiers;

    if (!notificationInterface->Initialize())
    {
        delete notificationInterface;
        notificationInterface = NULL;
    }

    LogPrintf("returning notificationInterface\n");
    return notificationInterface;
}

void CZMQPublisherInterface::UpdateSyncStatus()
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyStatus())
        {
            i++;
        }
        else
        {
            notifier->Shutdown();
            i = notifiers.erase(i);
        }
    }
}

void CZMQPublisherInterface::NumConnectionsChanged()
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyConnections())
        {
            i++;
        }
        else
        {
            notifier->Shutdown();
            i = notifiers.erase(i);
        }
    }
}

void CZMQPublisherInterface::UpdatedBlockTip(const CBlockIndex *pindex)
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyBlock(pindex))
        {
            i++;
        }
        else
        {
            notifier->Shutdown();
            i = notifiers.erase(i);
        }
    }
}

void CZMQPublisherInterface::SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, const CBlock* pblock)
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyTransaction(tx))
        {
            i++;
        }
        else
        {
            notifier->Shutdown();
            i = notifiers.erase(i);
        }
    }
}

void CZMQPublisherInterface::UpdatedZnode(CZnode &znode)
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyZnodeUpdate(znode))
        {
            i++;
        }
        else
        {
            notifier->Shutdown();
            i = notifiers.erase(i);
        }
    }
}
