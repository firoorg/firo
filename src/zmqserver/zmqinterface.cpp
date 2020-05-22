// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zmqinterface.h"
#include "zmqpublisher.h"
#include "zmqreplier.h"

#include "version.h"
#include "chainparamsbase.h"
#include "validation.h"
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

bool CZMQPublisherInterface::StartWorker()
{
    // Create worker
    worker = new boost::thread(boost::bind(&CZMQThreadPublisher::Thread));
    return true;
}

CZMQPublisherInterface::~CZMQPublisherInterface()
{
    Shutdown();

    for (std::list<CZMQAbstract*>::iterator i=notifiers.begin(); i!=notifiers.end(); ++i)
    {
        delete *i;
    }

    //destroy worker
    worker->interrupt();
}

CZMQPublisherInterface* CZMQPublisherInterface::Create()
{
    LogPrintf("in CreateWithArguments..\n");
    CZMQPublisherInterface* notificationInterface = NULL;
    std::map<std::string, CZMQFactory> factories;
    std::list<CZMQAbstract*> notifiers;

    // Ordering here implies ordering of topic publishing.
    std::vector<std::string> pubIndexes = {
        "pubblock", 
        "pubrawtx", 
        "pubblockinfo", 
        "pubbalance", 
        "pubznodeupdate", 
        "pubsettings",
        "pubstatus",
        "pubznodelist",
        "pubwalletsegment",
    };

    factories["pubblock"] = CZMQAbstract::Create<CZMQBlockDataTopic>;
    factories["pubrawtx"] = CZMQAbstract::Create<CZMQTransactionTopic>;
    factories["pubblockinfo"] = CZMQAbstract::Create<CZMQBlockInfoTopic>;
    factories["pubbalance"] = CZMQAbstract::Create<CZMQBalanceTopic>;
    factories["pubznodeupdate"] = CZMQAbstract::Create<CZMQZnodeTopic>;
    factories["pubsettings"] = CZMQAbstract::Create<CZMQSettingsTopic>;
    factories["pubstatus"] = CZMQAbstract::Create<CZMQAPIStatusTopic>;
    factories["pubwalletsegment"] = CZMQAbstract::Create<CZMQWalletSegmentTopic>;
    factories["pubznodelist"] = CZMQAbstract::Create<CZMQZnodeListTopic>;
    
    BOOST_FOREACH(string pubIndex, pubIndexes)
    {
        CZMQFactory factory = factories[pubIndex];
        CZMQAbstract *notifier = factory();
        string address = BaseParams().APIAddr();
        string port = pubIndex=="pubstatus" ? to_string(BaseParams().APIOpenPUBPort()) :
                                           to_string(BaseParams().APIAuthPUBPort());
        notifier->SetType("zmq" + pubIndex);
        notifier->SetAddress(address);
        notifier->SetPort(port);
        notifier->SetAuthority(address + port);
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

void CZMQPublisherInterface::NotifyAPIStatus()
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyAPIStatus())
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

void CZMQPublisherInterface::WalletSegment(const std::string &segment)
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyWalletSegment(segment))
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

void CZMQPublisherInterface::NotifyZnodeList()
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyZnodeList())
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

void CZMQPublisherInterface::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyBlock(pindexNew))
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

void CZMQPublisherInterface::WalletTransaction(const CTransaction& tx)
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

void CZMQPublisherInterface::UpdatedSettings(std::string update)
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifySettingsUpdate(update))
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

void CZMQPublisherInterface::UpdatedBalance()
{
    for (std::list<CZMQAbstract*>::iterator i = notifiers.begin(); i!=notifiers.end(); )
    {
        CZMQAbstract *notifier = *i;
        if (notifier->NotifyBalance())
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
