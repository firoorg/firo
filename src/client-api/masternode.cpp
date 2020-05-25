// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "client-api/server.h"
#include "client-api/protocol.h"
#include "client-api/wallet.h"

using namespace std;

UniValue masternodeupdate(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    
    UniValue ret(UniValue::VOBJ);
    string proTxHash;
    try {
        proTxHash = find_value(data, "proTxHash").get_str();
    }catch (const std::exception& e){
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }
    ret.push_back(Pair(proTxHash, data));
    return ret;
}

static const CAPICommand commands[] =
{ //  category      collection          actor (function)   authPort   authPassphrase warmupOk
  //  --------      ----------          ----------------   -----      -------------- --------
    { "masternode", "masternodeUpdate", &masternodeupdate, true,      false,         false  }
};
void RegisterZnodeAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
