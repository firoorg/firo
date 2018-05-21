#include <univalue.h>
#include "utilstrencodings.h"
#include "client-api/server.h"
//#include "qt/optionsmodel.h"

UniValue getSetting(const UniValue& params,bool fHelp)
{
	// push some logic here
	return 12;
}

static const CZMQCommand commands[] =
{ //  category              name                      actor (function)
  //  --------------------- ------------------------  -----------------------
    { "foo",				"bar",						&getSetting},
};

void SettingModuleZMQReqRep(CZMQTable &tableZMQ)
{
	for(unsigned int vcidx = 0 ;vcidx < ARRAYLEN(commands);vcidx++)
	{
		tableZMQ.appendCommand(commands[vcidx].name,&commands[vcidx]);
	}
}
