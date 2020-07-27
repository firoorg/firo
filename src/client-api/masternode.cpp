// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "client-api/server.h"
#include "client-api/protocol.h"
#include "client-api/wallet.h"
#include "evo/deterministicmns.h"
#include "validation.h"
#include "rpc/rpcevo.h"

using namespace std;

UniValue masternodelist(Type type, const UniValue& data, const UniValue& auth, bool fHelp){

    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return false;

    UniValue ret(UniValue::VOBJ);
    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(chainActive.Tip());
    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        if(deterministicMNManager->GetUpdates()[dmn->proTxHash]){
            std::string proTxHash = dmn->proTxHash.ToString();
            ret.push_back(Pair(proTxHash, BuildDMNListEntry(pwalletMain, dmn, true)));
            deterministicMNManager->GetUpdates().emplace(dmn->proTxHash, false);
        }
    });
    return ret;
}

UniValue masternodeupdate(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    
    UniValue ret(UniValue::VOBJ);
    UniValue masternode(UniValue::VOBJ);
    std::string strProTxHash;
    try {
        strProTxHash = find_value(data, "proTxHash").get_str();
    }catch (const std::exception& e){
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }

    ret.push_back(Pair(strProTxHash, data));
    return ret;
}

static const CAPICommand commands[] =
{ //  category      collection          actor (function)   authPort   authPassphrase warmupOk
  //  --------      ----------          ----------------   -----      -------------- --------
    { "masternode", "masternodeList",   &masternodelist,   true,      false,         false  },
    { "masternode", "masternodeUpdate", &masternodeupdate, true,      false,         false  }

};
void RegisterMasternodeAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
