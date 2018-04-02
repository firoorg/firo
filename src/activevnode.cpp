// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activevnode.h"
#include "vnode.h"
#include "vnode-sync.h"
#include "vnodeman.h"
#include "protocol.h"

extern CWallet *pwalletMain;

// Keep track of the active Vnode
CActiveVnode activeVnode;

void CActiveVnode::ManageState() {
    LogPrint("vnode", "CActiveVnode::ManageState -- Start\n");
    if (!fVNode) {
        LogPrint("vnode", "CActiveVnode::ManageState -- Not a vnode, returning\n");
        return;
    }

    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && !vnodeSync.IsBlockchainSynced()) {
        nState = ACTIVE_VNODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveVnode::ManageState -- %s: %s\n", GetStateString(), GetStatus());
        return;
    }

    if (nState == ACTIVE_VNODE_SYNC_IN_PROCESS) {
        nState = ACTIVE_VNODE_INITIAL;
    }

    LogPrint("vnode", "CActiveVnode::ManageState -- status = %s, type = %s, pinger enabled = %d\n",
             GetStatus(), GetTypeString(), fPingerEnabled);

    if (eType == VNODE_UNKNOWN) {
        ManageStateInitial();
    }

    if (eType == VNODE_REMOTE) {
        ManageStateRemote();
    } else if (eType == VNODE_LOCAL) {
        // Try Remote Start first so the started local vnode can be restarted without recreate vnode broadcast.
        ManageStateRemote();
        if (nState != ACTIVE_VNODE_STARTED)
            ManageStateLocal();
    }

    SendVnodePing();
}

std::string CActiveVnode::GetStateString() const {
    switch (nState) {
        case ACTIVE_VNODE_INITIAL:
            return "INITIAL";
        case ACTIVE_VNODE_SYNC_IN_PROCESS:
            return "SYNC_IN_PROCESS";
        case ACTIVE_VNODE_INPUT_TOO_NEW:
            return "INPUT_TOO_NEW";
        case ACTIVE_VNODE_NOT_CAPABLE:
            return "NOT_CAPABLE";
        case ACTIVE_VNODE_STARTED:
            return "STARTED";
        default:
            return "UNKNOWN";
    }
}

std::string CActiveVnode::GetStatus() const {
    switch (nState) {
        case ACTIVE_VNODE_INITIAL:
            return "Node just started, not yet activated";
        case ACTIVE_VNODE_SYNC_IN_PROCESS:
            return "Sync in progress. Must wait until sync is complete to start Vnode";
        case ACTIVE_VNODE_INPUT_TOO_NEW:
            return strprintf("Vnode input must have at least %d confirmations",
                             Params().GetConsensus().nVnodeMinimumConfirmations);
        case ACTIVE_VNODE_NOT_CAPABLE:
            return "Not capable vnode: " + strNotCapableReason;
        case ACTIVE_VNODE_STARTED:
            return "Vnode successfully started";
        default:
            return "Unknown";
    }
}

std::string CActiveVnode::GetTypeString() const {
    std::string strType;
    switch (eType) {
        case VNODE_UNKNOWN:
            strType = "UNKNOWN";
            break;
        case VNODE_REMOTE:
            strType = "REMOTE";
            break;
        case VNODE_LOCAL:
            strType = "LOCAL";
            break;
        default:
            strType = "UNKNOWN";
            break;
    }
    return strType;
}

bool CActiveVnode::SendVnodePing() {
    if (!fPingerEnabled) {
        LogPrint("vnode",
                 "CActiveVnode::SendVnodePing -- %s: vnode ping service is disabled, skipping...\n",
                 GetStateString());
        return false;
    }

    if (!mnodeman.Has(vin)) {
        strNotCapableReason = "Vnode not in vnode list";
        nState = ACTIVE_VNODE_NOT_CAPABLE;
        LogPrintf("CActiveVnode::SendVnodePing -- %s: %s\n", GetStateString(), strNotCapableReason);
        return false;
    }

    CVnodePing mnp(vin);
    if (!mnp.Sign(keyVnode, pubKeyVnode)) {
        LogPrintf("CActiveVnode::SendVnodePing -- ERROR: Couldn't sign Vnode Ping\n");
        return false;
    }

    // Update lastPing for our vnode in Vnode list
    if (mnodeman.IsVnodePingedWithin(vin, VNODE_MIN_MNP_SECONDS, mnp.sigTime)) {
        LogPrintf("CActiveVnode::SendVnodePing -- Too early to send Vnode Ping\n");
        return false;
    }

    mnodeman.SetVnodeLastPing(vin, mnp);

    LogPrintf("CActiveVnode::SendVnodePing -- Relaying ping, collateral=%s\n", vin.ToString());
    mnp.Relay();

    return true;
}

void CActiveVnode::ManageStateInitial() {
    LogPrint("vnode", "CActiveVnode::ManageStateInitial -- status = %s, type = %s, pinger enabled = %d\n",
             GetStatus(), GetTypeString(), fPingerEnabled);

    // Check that our local network configuration is correct
    if (!fListen) {
        // listen option is probably overwritten by smth else, no good
        nState = ACTIVE_VNODE_NOT_CAPABLE;
        strNotCapableReason = "Vnode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrintf("CActiveVnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    bool fFoundLocal = false;
    {
        LOCK(cs_vNodes);

        // First try to find whatever local address is specified by externalip option
        fFoundLocal = GetLocal(service) && CVnode::IsValidNetAddr(service);
        if (!fFoundLocal) {
            // nothing and no live connections, can't do anything for now
            if (vNodes.empty()) {
                nState = ACTIVE_VNODE_NOT_CAPABLE;
                strNotCapableReason = "Can't detect valid external address. Will retry when there are some connections available.";
                LogPrintf("CActiveVnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
                return;
            }
            // We have some peers, let's try to find our local address from one of them
            BOOST_FOREACH(CNode * pnode, vNodes)
            {
                if (pnode->fSuccessfullyConnected && pnode->addr.IsIPv4()) {
                    fFoundLocal = GetLocal(service, &pnode->addr) && CVnode::IsValidNetAddr(service);
                    if (fFoundLocal) break;
                }
            }
        }
    }

    if (!fFoundLocal) {
        nState = ACTIVE_VNODE_NOT_CAPABLE;
        strNotCapableReason = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
        LogPrintf("CActiveVnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort) {
            nState = ACTIVE_VNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Invalid port: %u - only %d is supported on mainnet.", service.GetPort(),
                                            mainnetDefaultPort);
            LogPrintf("CActiveVnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    } else if (service.GetPort() == mainnetDefaultPort) {
        nState = ACTIVE_VNODE_NOT_CAPABLE;
        strNotCapableReason = strprintf("Invalid port: %u - %d is only supported on mainnet.", service.GetPort(),
                                        mainnetDefaultPort);
        LogPrintf("CActiveVnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    LogPrintf("CActiveVnode::ManageStateInitial -- Checking inbound connection to '%s'\n", service.ToString());
    //TODO
    if (!ConnectNode(CAddress(service, NODE_NETWORK), NULL, false, true)) {
        nState = ACTIVE_VNODE_NOT_CAPABLE;
        strNotCapableReason = "Could not connect to " + service.ToString();
        LogPrintf("CActiveVnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Default to REMOTE
    eType = VNODE_REMOTE;

    // Check if wallet funds are available
    if (!pwalletMain) {
        LogPrintf("CActiveVnode::ManageStateInitial -- %s: Wallet not available\n", GetStateString());
        return;
    }

    if (pwalletMain->IsLocked()) {
        LogPrintf("CActiveVnode::ManageStateInitial -- %s: Wallet is locked\n", GetStateString());
        return;
    }

    if (pwalletMain->GetBalance() < VNODE_COIN_REQUIRED * COIN) {
        LogPrintf("CActiveVnode::ManageStateInitial -- %s: Wallet balance is < 3750 VRT\n", GetStateString());
        return;
    }

    // Choose coins to use
    CPubKey pubKeyCollateral;
    CKey keyCollateral;

    // If collateral is found switch to LOCAL mode
    if (pwalletMain->GetVnodeVinAndKeys(vin, pubKeyCollateral, keyCollateral)) {
        eType = VNODE_LOCAL;
    }

    LogPrint("vnode", "CActiveVnode::ManageStateInitial -- End status = %s, type = %s, pinger enabled = %d\n",
             GetStatus(), GetTypeString(), fPingerEnabled);
}

void CActiveVnode::ManageStateRemote() {
    LogPrint("vnode",
             "CActiveVnode::ManageStateRemote -- Start status = %s, type = %s, pinger enabled = %d, pubKeyVnode.GetID() = %s\n",
             GetStatus(), fPingerEnabled, GetTypeString(), pubKeyVnode.GetID().ToString());

    mnodeman.CheckVnode(pubKeyVnode);
    vnode_info_t infoMn = mnodeman.GetVnodeInfo(pubKeyVnode);
    if (infoMn.fInfoValid) {
        if (infoMn.nProtocolVersion != PROTOCOL_VERSION) {
            nState = ACTIVE_VNODE_NOT_CAPABLE;
            strNotCapableReason = "Invalid protocol version";
            LogPrintf("CActiveVnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (service != infoMn.addr) {
            nState = ACTIVE_VNODE_NOT_CAPABLE;
            // LogPrintf("service: %s\n", service.ToString());
            // LogPrintf("infoMn.addr: %s\n", infoMn.addr.ToString());
            strNotCapableReason = "Broadcasted IP doesn't match our external address. Make sure you issued a new broadcast if IP of this vnode changed recently.";
            LogPrintf("CActiveVnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (!CVnode::IsValidStateForAutoStart(infoMn.nActiveState)) {
            nState = ACTIVE_VNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Vnode in %s state", CVnode::StateToString(infoMn.nActiveState));
            LogPrintf("CActiveVnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (nState != ACTIVE_VNODE_STARTED) {
            LogPrintf("CActiveVnode::ManageStateRemote -- STARTED!\n");
            vin = infoMn.vin;
            service = infoMn.addr;
            fPingerEnabled = true;
            nState = ACTIVE_VNODE_STARTED;
        }
    } else {
        nState = ACTIVE_VNODE_NOT_CAPABLE;
        strNotCapableReason = "Vnode not in vnode list";
        LogPrintf("CActiveVnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
    }
}

void CActiveVnode::ManageStateLocal() {
    LogPrint("vnode", "CActiveVnode::ManageStateLocal -- status = %s, type = %s, pinger enabled = %d\n",
             GetStatus(), GetTypeString(), fPingerEnabled);
    if (nState == ACTIVE_VNODE_STARTED) {
        return;
    }

    // Choose coins to use
    CPubKey pubKeyCollateral;
    CKey keyCollateral;

    if (pwalletMain->GetVnodeVinAndKeys(vin, pubKeyCollateral, keyCollateral)) {
        int nInputAge = GetInputAge(vin);
        if (nInputAge < Params().GetConsensus().nVnodeMinimumConfirmations) {
            nState = ACTIVE_VNODE_INPUT_TOO_NEW;
            strNotCapableReason = strprintf(_("%s - %d confirmations"), GetStatus(), nInputAge);
            LogPrintf("CActiveVnode::ManageStateLocal -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }

        {
            LOCK(pwalletMain->cs_wallet);
            pwalletMain->LockCoin(vin.prevout);
        }

        CVnodeBroadcast mnb;
        std::string strError;
        if (!CVnodeBroadcast::Create(vin, service, keyCollateral, pubKeyCollateral, keyVnode,
                                     pubKeyVnode, strError, mnb)) {
            nState = ACTIVE_VNODE_NOT_CAPABLE;
            strNotCapableReason = "Error creating mastenode broadcast: " + strError;
            LogPrintf("CActiveVnode::ManageStateLocal -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }

        fPingerEnabled = true;
        nState = ACTIVE_VNODE_STARTED;

        //update to vnode list
        LogPrintf("CActiveVnode::ManageStateLocal -- Update Vnode List\n");
        mnodeman.UpdateVnodeList(mnb);
        mnodeman.NotifyVnodeUpdates();

        //send to all peers
        LogPrintf("CActiveVnode::ManageStateLocal -- Relay broadcast, vin=%s\n", vin.ToString());
        mnb.RelayVNode();
    }
}
