// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeznode.h"
#include "validationinterface.h"
#include "znodeman.h"
#include "univalue.h"
#include "znode-sync.h"
#include "client-api/server.h"
#include "client-api/protocol.h"
#include <client-api/wallet.h>
#include <unordered_map>

using namespace std;
#include "znodeconfig.h"

UniValue znodecontrol(Type type, const UniValue& data, const UniValue& auth, bool fHelp){

    string method = find_value(data, "method").get_str();

    UniValue overall(UniValue::VOBJ);
    UniValue detail(UniValue::VOBJ);
    UniValue ret(UniValue::VOBJ);
    
    int nSuccessful = 0;
    int nFailed = 0;

    if (method == "start-alias") {

        string alias = find_value(data, "alias").get_str();

        bool fFound = false;

        UniValue status(UniValue::VOBJ);
        status.push_back(Pair("alias", alias));

        BOOST_FOREACH(CZnodeConfig::CZnodeEntry mne, znodeConfig.getEntries()) {
            if (mne.getAlias() == alias) {
                fFound = true;
                std::string strError;
                CZnodeBroadcast mnb;

                bool fResult = CZnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(),
                                                            mne.getOutputIndex(), strError, mnb);
                status.push_back(Pair("success", fResult));
                if (fResult) {
                    nSuccessful++;
                    mnodeman.UpdateZnodeList(mnb);
                    mnb.RelayZNode();
                } else {
                    nFailed++;
                    status.push_back(Pair("info", strError));
                }
                mnodeman.NotifyZnodeUpdates();
                break;
            }
        }

        if (!fFound) {
            nFailed++;
            status.push_back(Pair("success", false));
            status.push_back(Pair("info", "Could not find alias in config. Verify with list-conf."));
        }

        detail.push_back(Pair("status", status));
    }

    else if (method == "start-all" || method == "start-missing") {
        {
            LOCK(pwalletMain->cs_wallet);
            EnsureWalletIsUnlocked();
        }

        if ((method == "start-missing") && !znodeSync.IsZnodeListSynced()) {
            throw JSONAPIError(API_CLIENT_IN_INITIAL_DOWNLOAD,
                               "You can't use this command until znode list is synced");
        }

        BOOST_FOREACH(CZnodeConfig::CZnodeEntry mne, znodeConfig.getEntries()) {
            std::string strError;

            CTxIn vin = CTxIn(uint256S(mne.getTxHash()), uint32_t(atoi(mne.getOutputIndex().c_str())));
            CZnode *pmn = mnodeman.Find(vin);
            CZnodeBroadcast mnb;

            if (method == "start-missing" && pmn) continue;

            bool fResult = CZnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(),
                                                        mne.getOutputIndex(), strError, mnb);

            UniValue status(UniValue::VOBJ);
            status.push_back(Pair("alias", mne.getAlias()));
            status.push_back(Pair("success", fResult));

            if (fResult) {
                nSuccessful++;
                mnodeman.UpdateZnodeList(mnb);
                mnb.RelayZNode();
            } else {
                nFailed++;
                status.push_back(Pair("info", strError));
            }

            detail.push_back(Pair("status", status));
        }
        mnodeman.NotifyZnodeUpdates();

    }

    else if(method=="update-status"){
        
    }
    else {
        throw runtime_error("Method not found.");
    }

    overall.push_back(Pair("successful", nSuccessful));
    overall.push_back(Pair("failed", nFailed));
    overall.push_back(Pair("total", nSuccessful + nFailed));

    ret.push_back(Pair("overall", overall));
    ret.push_back(Pair("detail", detail));

    return ret;
}

UniValue znodelist(Type type, const UniValue& data, const UniValue& auth, bool fHelp){

    if(!znodeSync.IsSynced()){
        throw runtime_error("Znode data not yet finished syncing.");
    }
    switch(type){
        case Initial: {
            mnodeman.UpdateLastPaid();
            UniValue ret(UniValue::VOBJ);
            UniValue data(UniValue::VOBJ);

            string myZnode = activeZnode.vin.prevout.ToStringShort();

            std::unordered_map<std::string, int> ranks;

            std::vector <std::pair<int, CZnode>> vZnodeRanks = mnodeman.GetZnodeRanks();
            BOOST_FOREACH(PAIRTYPE(int, CZnode) & s, vZnodeRanks)
            {
                std::string payee = CBitcoinAddress(s.second.pubKeyCollateralAddress.GetID()).ToString();
                ranks[payee] = s.first;
            }

            std::vector <CZnode> vZnodes = mnodeman.GetFullZnodeVector();
            BOOST_FOREACH(CZnode & mn, vZnodes)
            {
                std::string payee = CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString();
                data.replace(payee, mn.ToJSON());
            }

            ret.push_back(Pair("data", data));

            return ret;

            break;
        }
        default: {

        }
    }

    return true;
}

UniValue znodeupdate(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("data", data.get_obj()));
    return ret;
}

static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "znode",              "znodeList",       &znodelist,               true,      false,           false  },
    { "znode",              "znodeControl",    &znodecontrol,            true,      false,           false  },
    { "znode",              "znodeUpdate",     &znodeupdate,             true,      false,           false  }
};
void RegisterZnodeAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}