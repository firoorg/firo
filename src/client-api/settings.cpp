// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "znodeconfig.h"
#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "client-api/server.h"
#include "rpc/server.h"
#include "streams.h"
#include "znode-sync.h"
#include "activeznode.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "wallet/wallet.h"
#include "wallet/rpcwallet.cpp"
#include <stdint.h>
#include <client-api/protocol.h>

#include "znodeman.h"

#include <zmqserver/zmqabstract.h>

#include <univalue.h>

#include <boost/thread/thread.hpp> // boost::thread::interrupt

namespace fs = boost::filesystem;
using namespace std::chrono;
using namespace std;


bool WriteAPISetting(string program){
    //get path (maybe separate function, pass?)
    // program=daemon || client

    UniValye

}

UniValue GetSettingsData(){
    fs::path const &path = CreateSettingsFile();

    // get data as ifstream
    std::ifstream SettingsIn(path.string());

    // parse as std::string
    std::string SettingsStr((std::istreambuf_iterator<char>(SettingsIn)), std::istreambuf_iterator<char>());

    // finally as UniValue
    UniValue SettingsUni(UniValue::VOBJ);
    SettingsUni.read(SettingsStr);

    UniValue SettingsData(UniValue::VOBJ);
    if(!SettingsUni["data"].isNull()){
        SettingsData = SettingsUni["data"];
    }

    return SettingsData;
}

UniValue setting(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    //type==create
    //get path

}

static const CAPISettings settings[] =
{ //  category              settingName         restartRequired  CLI arg
  //  --------------------- ------------       ---------------- ----------
    { "misc",               "proxy",                true,      "proxy"               },
    { "wallet",             "separateProxyTor",     true,      "onion"               },
    { "wallet",             "SpendZeroConfChange",  true,      "spendzeroconfchange" },
    { "wallet",             "strThirdPartyTxUrls",  true,      ""                    },
    { "wallet",             "language",             true,      "lang"                },
    { "wallet",             "nDatabaseCache",       true,      "dbcache"             },
    { "wallet",             "nThreadsScriptVerif",  true,      "par"                 },
    { "wallet",             "fListen",              true,      "listen"              }
    
};
void RegisterAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
