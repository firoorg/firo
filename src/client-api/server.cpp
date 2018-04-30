#include "client-api/server.h"
#include "rpc/server.h"

static bool fZMQRunning = false;

bool IsZMQRunning() {
	return fZMQRunning;
}

static const CZMQCommand vZMQCommands[] =
{ //  category              name                      actor (function)       
  //  --------------------- ------------------------  -----------------------  
  { "addressindex",       "getaddressbalance",      &getaddressbalance    },
};

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

CZMQTable tableZMQ;
