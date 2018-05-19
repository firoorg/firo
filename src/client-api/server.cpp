#include "client-api/server.h"
#include "rpc/server.h"
#include <univalue.h>
#include <boost/signals2/signal.hpp>

static bool fZMQRunning = false;

bool IsZMQRunning() {
	return fZMQRunning;
}

static const CZMQCommand vZMQCommands[] =
{ //  category              name                      actor (function)       
  //  --------------------- ------------------------  -----------------------  
  { "addressindex",       "getaddressbalance",      &getaddressbalance    },
};

static struct CZMQSignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CZMQCommand&)> PreCommand;
    boost::signals2::signal<void (const CZMQCommand&)> PostCommand;
} g_zmqSignals;

CZMQTable::CZMQTable()
{
	unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vZMQCommands) / sizeof(vZMQCommands[0])); vcidx++)
    {
        const CZMQCommand *pcmd;

        pcmd = &vZMQCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}



const CZMQCommand *CZMQTable::operator[](const std::string &name) const
{
	std::map<std::string, const CZMQCommand*>::const_iterator it = mapCommands.find(name);
	if (it == mapCommands.end())
		return NULL;
	return (*it).second;
}

bool CZMQTable::appendCommand(const std::string& name, const CZMQCommand* pcmd)
{
    if (IsZMQRunning())
        return false;

    // don't allow overwriting for now
    std::map<std::string, const CZMQCommand*>::const_iterator it = mapCommands.find(name);
    if (it != mapCommands.end())
        return false;

    mapCommands[name] = pcmd;
    return true;
}

UniValue CZMQTable::execute(const std::string &strMethod, const UniValue &params) const
{
    // Return immediately if in warmup
    // { don't think necessary
    //     LOCK(cs_rpcWarmup);
    //     if (fRPCInWarmup)
    //         throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
    // }

    // Find method
    const CZMQCommand *pcmd = tableZMQ[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    g_zmqSignals.PreCommand (*pcmd);

    try
    {
        // Execute
        return pcmd->actor(params, false);
    }
    catch (const std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    g_zmqSignals.PostCommand(*pcmd);
}

CZMQTable tableZMQ;
