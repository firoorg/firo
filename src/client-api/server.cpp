#include "client-api/server.h"
#include "rpc/server.h"
#include <univalue.h>
#include <boost/signals2/signal.hpp>

static bool fAPIRunning = false;

bool IsAPIRunning() {
	return fAPIRunning;
}

static const CAPICommand vAPICommands[] =
{ //  category              name                      actor (function)       
  //  --------------------- ------------------------  -----------------------  
  { "addressindex",       "getaddressbalance",      &getaddressbalance    },
};

static struct CAPISignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CAPICommand&)> PreCommand;
    boost::signals2::signal<void (const CAPICommand&)> PostCommand;
} g_apiSignals;

CAPITable::CAPITable()
{
	unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vAPICommands) / sizeof(vAPICommands[0])); vcidx++)
    {
        const CAPICommand *pcmd;

        pcmd = &vAPICommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}



const CAPICommand *CAPITable::operator[](const std::string &name) const
{
	std::map<std::string, const CAPICommand*>::const_iterator it = mapCommands.find(name);
	if (it == mapCommands.end())
		return NULL;
	return (*it).second;
}

bool CAPITable::appendCommand(const std::string& name, const CAPICommand* pcmd)
{
    if (IsAPIRunning())
        return false;

    // don't allow overwriting for now
    std::map<std::string, const CAPICommand*>::const_iterator it = mapCommands.find(name);
    if (it != mapCommands.end())
        return false;

    mapCommands[name] = pcmd;
    return true;
}

UniValue CAPITable::execute(const std::string &strMethod, const UniValue &params) const
{
    // Return immediately if in warmup
    // { don't think necessary
    //     LOCK(cs_rpcWarmup);
    //     if (fRPCInWarmup)
    //         throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
    // }

    // Find method
    const CAPICommand *pcmd = tableAPI[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    g_apiSignals.PreCommand (*pcmd);

    try
    {
        // Execute
        return pcmd->actor(params, false);
    }
    catch (const std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    g_apiSignals.PostCommand(*pcmd);
}

CAPITable tableAPI;
