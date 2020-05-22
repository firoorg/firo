// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeznode.h"
#include "validationinterface.h"
#include "znodeman.h"
#include "univalue.h"
#include "znodesync-interface.h"
#include "znode-sync.h"
#include "znodeconfig.h"
#include "client-api/server.h"
#include "client-api/protocol.h"
#include <client-api/wallet.h>
#include <unordered_map>

using namespace std;

bool GetZnodePayeeAddress(const std::string& txHash, const std::string& n, CBitcoinAddress& address){

    const CWalletTx* wtx = pwalletMain->GetWalletTx(uint256S(txHash));
    if(wtx==NULL)
        return false;

    CTxDestination destination;
    const CTxOut &txout = wtx->tx->vout[stoi(n)];
    if (!ExtractDestination(txout.scriptPubKey, destination))
        return false;

    address.Set(destination);

    return true;
}

UniValue znodekey(Type type, const UniValue& data, const UniValue& auth, bool fHelp){

    UniValue key(UniValue::VOBJ);
    CKey secret;
    secret.MakeNewKey(false);

    key.push_back(Pair("key", CBitcoinSecret(secret).ToString()));

    return key;
}

UniValue znodecontrol(Type type, const UniValue& data, const UniValue& auth, bool fHelp){

    string method;
    try {
        method = find_value(data, "method").get_str();
    }catch (const std::exception& e){
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }

    UniValue overall(UniValue::VOBJ);
    UniValue detail(UniValue::VOBJ);
    UniValue ret(UniValue::VOBJ);

    int nSuccessful = 0;
    int nFailed = 0;

    if (method == "start-alias") {

        string alias;
        try {
            alias = find_value(data, "alias").get_str();
        }catch (const std::exception& e){
            throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
        }

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
            EnsureWalletIsUnlocked(pwalletMain);
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

    UniValue ret(UniValue::VOBJ);
    UniValue nodes(UniValue::VOBJ);

    int fIndex = 0;
    BOOST_FOREACH(CZnodeConfig::CZnodeEntry mne, znodeConfig.getEntries()) {
        const std::string& txHash = mne.getTxHash();
        const std::string& outputIndex = mne.getOutputIndex();
        CBitcoinAddress address;
        std::string key = txHash + outputIndex;
        CZnode* mn = mnodeman.Find(txHash, outputIndex);

        UniValue node(UniValue::VOBJ);
        if(mn==NULL){
            node = mne.ToJSON();
            node.push_back(Pair("position", fIndex++));
            if(GetZnodePayeeAddress(txHash, outputIndex, address))
                node.push_back(Pair("payeeAddress", address.ToString()));
        }else{
            node = mn->ToJSON();
        }
        nodes.replace(key, node);
    }

    /*
     * If the Znode list is not yet synced, return the wallet Znodes, as described in znode.conf
     * if it is, process all Znodes, and return along with wallet Znodes.
     * (if the wallet Znode has started, it will be replaced in the synced list).
     */
    if(!znodeSync.IsSynced()){
        ret.push_back(Pair("nodes", nodes));
        ret.push_back(Pair("total", mnodeman.CountZnodes()));
        return ret;
    }

    std::vector <CZnode> vZnodes = mnodeman.GetFullZnodeVector();
    BOOST_FOREACH(CZnode & mn, vZnodes) {
        std::string txHash = mn.vin.prevout.hash.ToString().substr(0,64);
        std::string outputIndex = to_string(mn.vin.prevout.n);
        std::string key = txHash + outputIndex;

        // only process wallet Znodes - they are already in "nodes", so if we find it, replace with update
        if(!find_value(nodes, key).isNull())
            nodes.replace(key, mn.ToJSON());
    }

    ret.push_back(Pair("nodes", nodes));
    ret.push_back(Pair("total", mnodeman.CountZnodes()));

    return ret;

}

UniValue znodeupdate(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    UniValue ret(UniValue::VOBJ);
    UniValue outpoint(UniValue::VOBJ);
    string key;
    // We already have the return data in the "data" object, here we simply form the key.
    try {
        outpoint = find_value(data, "outpoint").get_obj();
        key = find_value(outpoint, "txid").get_str() +  find_value(outpoint, "index").get_str();
    }catch (const std::exception& e){
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }
    ret.push_back(Pair(key, data));
    return ret;
}

static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "znode",              "znodeControl",    &znodecontrol,            true,      true,            false  },
    { "znode",              "znodeKey",        &znodekey,                true,      false,           false  },
    { "znode",              "znodeList",       &znodelist,               true,      false,           false  },
    { "znode",              "znodeUpdate",     &znodeupdate,             true,      false,           false  }
};
void RegisterZnodeAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
