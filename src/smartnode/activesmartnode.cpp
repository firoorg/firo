// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activesmartnode.h"
#include "protocol.h"
#include "smartnode.h"
#include "smartnodesync.h"
#include "smartnodeman.h"

// Keep track of the active Smartnode
CActiveSmartnode activeSmartnode;

void CActiveSmartnode::ManageState(CConnman& connman)
{
    LogPrint("smartnode", "CActiveSmartnode::ManageState -- Start\n");
    if(!fSmartNode) {
        LogPrint("smartnode", "CActiveSmartnode::ManageState -- Not a smartnode, returning\n");
        return;
    }

    if(Params().NetworkIDString() != CBaseChainParams::REGTEST && !smartnodeSync.IsBlockchainSynced()) {
        nState = ACTIVE_SMARTNODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveSmartnode::ManageState -- %s: %s\n", GetStateString(), GetStatus());
        return;
    }

    if(nState == ACTIVE_SMARTNODE_SYNC_IN_PROCESS) {
        nState = ACTIVE_SMARTNODE_INITIAL;
    }

    LogPrint("smartnode", "CActiveSmartnode::ManageState -- status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);

    if(eType == SMARTNODE_UNKNOWN) {
        ManageStateInitial(connman);
    }

    if(eType == SMARTNODE_REMOTE) {
        ManageStateRemote();
    }

    SendSmartnodePing(connman);
}

std::string CActiveSmartnode::GetStateString() const
{
    switch (nState) {
        case ACTIVE_SMARTNODE_INITIAL:         return "INITIAL";
        case ACTIVE_SMARTNODE_SYNC_IN_PROCESS: return "SYNC_IN_PROCESS";
        case ACTIVE_SMARTNODE_INPUT_TOO_NEW:   return "INPUT_TOO_NEW";
        case ACTIVE_SMARTNODE_NOT_CAPABLE:     return "NOT_CAPABLE";
        case ACTIVE_SMARTNODE_STARTED:         return "STARTED";
        default:                                return "UNKNOWN";
    }
}

std::string CActiveSmartnode::GetStatus() const
{
    switch (nState) {
        case ACTIVE_SMARTNODE_INITIAL:         return "Node just started, not yet activated";
        case ACTIVE_SMARTNODE_SYNC_IN_PROCESS: return "Sync in progress. Must wait until sync is complete to start Smartnode";
        case ACTIVE_SMARTNODE_INPUT_TOO_NEW:   return strprintf("Smartnode input must have at least %d confirmations", Params().GetConsensus().nSmartnodeMinimumConfirmations);
        case ACTIVE_SMARTNODE_NOT_CAPABLE:     return "Not capable smartnode: " + strNotCapableReason;
        case ACTIVE_SMARTNODE_STARTED:         return "Smartnode successfully started";
        default:                                return "Unknown";
    }
}

std::string CActiveSmartnode::GetTypeString() const
{
    std::string strType;
    switch(eType) {
    case SMARTNODE_REMOTE:
        strType = "REMOTE";
        break;
    default:
        strType = "UNKNOWN";
        break;
    }
    return strType;
}

bool CActiveSmartnode::SendSmartnodePing(CConnman& connman)
{
    if(!fPingerEnabled) {
        LogPrint("smartnode", "CActiveSmartnode::SendSmartnodePing -- %s: smartnode ping service is disabled, skipping...\n", GetStateString());
        return false;
    }

    if(!mnodeman.Has(outpoint)) {
        strNotCapableReason = "Smartnode not in smartnode list";
        nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
        LogPrintf("CActiveSmartnode::SendSmartnodePing -- %s: %s\n", GetStateString(), strNotCapableReason);
        return false;
    }

    CSmartnodePing mnp(outpoint);
    mnp.nSentinelVersion = nSentinelVersion;
    mnp.fSentinelIsCurrent =
            (abs(GetAdjustedTime() - nSentinelPingTime) < SMARTNODE_WATCHDOG_MAX_SECONDS);
    if(!mnp.Sign(keySmartnode, pubKeySmartnode)) {
        LogPrintf("CActiveSmartnode::SendSmartnodePing -- ERROR: Couldn't sign Smartnode Ping\n");
        return false;
    }

    // Update lastPing for our smartnode in Smartnode list
    if(mnodeman.IsSmartnodePingedWithin(outpoint, SMARTNODE_MIN_MNP_SECONDS, mnp.sigTime)) {
        LogPrintf("CActiveSmartnode::SendSmartnodePing -- Too early to send Smartnode Ping\n");
        return false;
    }

    mnodeman.SetSmartnodeLastPing(outpoint, mnp);

    LogPrintf("CActiveSmartnode::SendSmartnodePing -- Relaying ping, collateral=%s\n", outpoint.ToStringShort());
    mnp.Relay(connman);

    return true;
}

bool CActiveSmartnode::UpdateSentinelPing(int version)
{
    nSentinelVersion = version;
    nSentinelPingTime = GetAdjustedTime();

    return true;
}

void CActiveSmartnode::ManageStateInitial(CConnman& connman)
{
    LogPrint("smartnode", "CActiveSmartnode::ManageStateInitial -- status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);

    // Check that our local network configuration is correct
    if (!fListen) {
        // listen option is probably overwritten by smth else, no good
        nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
        strNotCapableReason = "Smartnode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrintf("CActiveSmartnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // First try to find whatever local address is specified by externalip option
    bool fFoundLocal = GetLocal(service) && CSmartnode::IsValidNetAddr(service);
    if(!fFoundLocal) {
        bool empty = true;
        // If we have some peers, let's try to find our local address from one of them
        connman.ForEachNodeContinueIf(CConnman::AllNodes, [&fFoundLocal, &empty, this](CNode* pnode) {
            empty = false;
            if (pnode->addr.IsIPv4())
                fFoundLocal = GetLocal(service, &pnode->addr) && CSmartnode::IsValidNetAddr(service);
            return !fFoundLocal;
        });
        // nothing and no live connections, can't do anything for now
        if (empty) {
            nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
            strNotCapableReason = "Can't detect valid external address. Will retry when there are some connections available.";
            LogPrintf("CActiveSmartnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    }

    if(!fFoundLocal) {
        nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
        strNotCapableReason = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
        LogPrintf("CActiveSmartnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(service.GetPort() != mainnetDefaultPort) {
            nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Invalid port: %u - only %d is supported on mainnet.", service.GetPort(), mainnetDefaultPort);
            LogPrintf("CActiveSmartnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    } else if(service.GetPort() == mainnetDefaultPort) {
        nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
        strNotCapableReason = strprintf("Invalid port: %u - %d is only supported on mainnet.", service.GetPort(), mainnetDefaultPort);
        LogPrintf("CActiveSmartnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    LogPrintf("CActiveSmartnode::ManageStateInitial -- Checking inbound connection to '%s'\n", service.ToString());

    if(!connman.ConnectNode(CAddress(service, NODE_NETWORK), NULL, true)) {
        nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
        strNotCapableReason = "Could not connect to " + service.ToString();
        LogPrintf("CActiveSmartnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Default to REMOTE
    eType = SMARTNODE_REMOTE;

    LogPrint("smartnode", "CActiveSmartnode::ManageStateInitial -- End status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);
}

void CActiveSmartnode::ManageStateRemote()
{
    LogPrint("smartnode", "CActiveSmartnode::ManageStateRemote -- Start status = %s, type = %s, pinger enabled = %d, pubKeySmartnode.GetID() = %s\n", 
             GetStatus(), GetTypeString(), fPingerEnabled, pubKeySmartnode.GetID().ToString());

    mnodeman.CheckSmartnode(pubKeySmartnode, true);
    smartnode_info_t infoMn;
    if(mnodeman.GetSmartnodeInfo(pubKeySmartnode, infoMn)) {
        if(infoMn.nProtocolVersion != PROTOCOL_VERSION) {
            nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
            strNotCapableReason = "Invalid protocol version";
            LogPrintf("CActiveSmartnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(service != infoMn.addr) {
            nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
            strNotCapableReason = "Broadcasted IP doesn't match our external address. Make sure you issued a new broadcast if IP of this smartnode changed recently.";
            LogPrintf("CActiveSmartnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(!CSmartnode::IsValidStateForAutoStart(infoMn.nActiveState)) {
            nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Smartnode in %s state", CSmartnode::StateToString(infoMn.nActiveState));
            LogPrintf("CActiveSmartnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(nState != ACTIVE_SMARTNODE_STARTED) {
            LogPrintf("CActiveSmartnode::ManageStateRemote -- STARTED!\n");
            outpoint = infoMn.vin.prevout;
            service = infoMn.addr;
            fPingerEnabled = true;
            nState = ACTIVE_SMARTNODE_STARTED;
        }
    }
    else {
        nState = ACTIVE_SMARTNODE_NOT_CAPABLE;
        strNotCapableReason = "Smartnode not in smartnode list";
        LogPrintf("CActiveSmartnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
    }
}
