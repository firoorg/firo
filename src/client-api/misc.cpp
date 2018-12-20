// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "znodeman.h"
#include "main.h"
#include "init.h"
#include "util.h"
#include "client-api/server.h"
#include "rpc/server.h"
#include "znode-sync.h"
#include "wallet/wallet.h"
#include "znode.h"
#include "activeznode.h"
#include <zmqserver/zmqabstract.h>
#include "univalue.h"

namespace fs = boost::filesystem;
using namespace boost::chrono;
using namespace std;

UniValue apistatus(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    UniValue obj(UniValue::VOBJ);
    UniValue modules(UniValue::VOBJ);
    
    CZnode *myZnode = mnodeman.Find(activeZnode.vin);
    if(myZnode!=NULL){
        UniValue znodeObj(UniValue::VOBJ);
        znodeObj = myZnode->ToJSON();
        obj.push_back(Pair("myZnode",znodeObj));
    }else {
        obj.push_back(Pair("myZnode",NullUniValue));
    }

    modules.push_back(Pair("API", !APIIsInWarmup()));
    modules.push_back(Pair("Znode", znodeSync.IsSynced()));

    obj.push_back(Pair("version", CLIENT_VERSION));
    obj.push_back(Pair("protocolVersion", PROTOCOL_VERSION));
    if (pwalletMain) {
        obj.push_back(Pair("walletVersion", pwalletMain->GetVersion()));
    }
    if (pwalletMain){
        obj.push_back(Pair("walletLock",    pwalletMain->IsCrypted()));
        if(nWalletUnlockTime>0){
            obj.push_back(Pair("unlockedUntil", nWalletUnlockTime));
        }
    }

    obj.push_back(Pair("dataDir",       GetDataDir(true).string()));
    obj.push_back(Pair("network",       ChainNameFromCommandLine()));
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("devAuth",       CZMQAbstract::DEV_AUTH));
    obj.push_back(Pair("synced",        znodeSync.GetBlockchainSynced()));
    obj.push_back(Pair("modules",       modules));

    return obj;
}

UniValue backup(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    string directory = find_value(data, "directory").get_str();

    milliseconds secs = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );
    UniValue firstSeenAt = secs.count();
    string filename = "zcoin_backup-" + to_string(firstSeenAt.get_int64()) + ".zip";

    fs::path backupPath (directory);
    backupPath /= filename;

    vector<string> filePaths;
    vector<string> folderPaths;

    filePaths.push_back(DEFAULT_WALLET_DAT);
    folderPaths.push_back(PERSISTENT_FILENAME);

    if(!CreateZipFile(GetDataDir().string() + "/", folderPaths, filePaths, backupPath.string())){
        throw JSONRPCError(API_MISC_ERROR, "Failed to create backup");
    }

    return true;
}

UniValue stop(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp)
        throw runtime_error(
            "stop\n"
            "\nStop Zcoin server.");
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client.
    StartShutdown();
    return true;
}

static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "misc",               "apiStatus",       &apistatus,               false,     false,           true   },
    { "misc",               "backup",          &backup,                  true,      false,           false  },
    { "misc",               "stop",            &stop,                    true,      false,           false  }
};

void RegisterMiscAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}