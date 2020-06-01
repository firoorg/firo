// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeznode.h"
#include "checkpoints.h"
#include "validation.h"
#include "znode.h"
#include "znode-payments.h"
#include "znode-sync.h"
#include "znodeman.h"
#include "netfulfilledman.h"
#include "spork.h"
#include "darksend.h"
#include "net_processing.h"
#include "netmessagemaker.h"
#include "util.h"

// TODO: remove this when upgraded to dash latest version
#define cs_vNodes (g_connman->cs_vNodes)
#define vNodes (g_connman->vNodes)

class CZnodeSync;

CZnodeSync znodeSync;

bool CZnodeSync::CheckNodeHeight(CNode *pnode, bool fDisconnectStuckNodes) {
    CNodeStateStats stats;
    if (!GetNodeStateStats(pnode->id, stats) || stats.nCommonHeight == -1 || stats.nSyncHeight == -1) return false; // not enough info about this peer

    // Check blocks and headers, allow a small error margin of 1 block
    if (pCurrentBlockIndex->nHeight - 1 > stats.nCommonHeight) {
        // This peer probably stuck, don't sync any additional data from it
        if (fDisconnectStuckNodes) {
            // Disconnect to free this connection slot for another peer.
            pnode->fDisconnect = true;
            LogPrintf("CZnodeSync::CheckNodeHeight -- disconnecting from stuck peer, nHeight=%d, nCommonHeight=%d, peer=%d\n",
                      pCurrentBlockIndex->nHeight, stats.nCommonHeight, pnode->id);
        } else {
            LogPrintf("CZnodeSync::CheckNodeHeight -- skipping stuck peer, nHeight=%d, nCommonHeight=%d, peer=%d\n",
                      pCurrentBlockIndex->nHeight, stats.nCommonHeight, pnode->id);
        }
        return false;
    } else if (pCurrentBlockIndex->nHeight < stats.nSyncHeight - 1) {
        // This peer announced more headers than we have blocks currently
        LogPrint("znode", "CZnodeSync::CheckNodeHeight -- skipping peer, who announced more headers than we have blocks currently, nHeight=%d, nSyncHeight=%d, peer=%d\n",
                  pCurrentBlockIndex->nHeight, stats.nSyncHeight, pnode->id);
        return false;
    }

    return true;
}

bool CZnodeSync::IsBlockchainSynced(bool fBlockAccepted) {
    static bool fBlockchainSynced = false;
    static int64_t nTimeLastProcess = GetTime();
    static int nSkipped = 0;
    static bool fFirstBlockAccepted = false;

    // If the last call to this function was more than 60 minutes ago 
    // (client was in sleep mode) reset the sync process
    if (GetTime() - nTimeLastProcess > 60 * 60) {
        LogPrintf("CZnodeSync::IsBlockchainSynced time-check fBlockchainSynced=%s\n", 
                  fBlockchainSynced);
        Reset();
        fBlockchainSynced = false;
    }

    if (!pCurrentBlockIndex || !pindexBestHeader || fImporting || fReindex) 
        return false;

    if (fBlockAccepted) {
        // This should be only triggered while we are still syncing.
        if (!IsSynced()) {
            // We are trying to download smth, reset blockchain sync status.
            fFirstBlockAccepted = true;
            fBlockchainSynced = false;
            nTimeLastProcess = GetTime();
            return false;
        }
    } else {
        // Dont skip on REGTEST to make the tests run faster.
        if(Params().NetworkIDString() != CBaseChainParams::REGTEST) {
            // skip if we already checked less than 1 tick ago.
            if (GetTime() - nTimeLastProcess < ZNODE_SYNC_TICK_SECONDS) {
                nSkipped++;
                return fBlockchainSynced;
            }
        }
    }

    LogPrint("znode-sync", 
             "CZnodeSync::IsBlockchainSynced -- state before check: %ssynced, skipped %d times\n", 
             fBlockchainSynced ? "" : "not ", 
             nSkipped);

    nTimeLastProcess = GetTime();
    nSkipped = 0;

    if (fBlockchainSynced){
        return true;
    }

    std::vector < CNode * > vNodesCopy = g_connman->CopyNodeVector();
    // We have enough peers and assume most of them are synced
    if (vNodesCopy.size() >= ZNODE_SYNC_ENOUGH_PEERS) {
        // Check to see how many of our peers are (almost) at the same height as we are
        int nNodesAtSameHeight = 0;
        BOOST_FOREACH(CNode * pnode, vNodesCopy)
        {
            // Make sure this peer is presumably at the same height
            if (!CheckNodeHeight(pnode)) {
                continue;
            }
            nNodesAtSameHeight++;
            // if we have decent number of such peers, most likely we are synced now
            if (nNodesAtSameHeight >= ZNODE_SYNC_ENOUGH_PEERS) {
                LogPrintf("CZnodeSync::IsBlockchainSynced -- found enough peers on the same height as we are, done\n");
                fBlockchainSynced = true;
                g_connman->ReleaseNodeVector(vNodesCopy);
                return true;
            }
        }
    }
    g_connman->ReleaseNodeVector(vNodesCopy);

    // wait for at least one new block to be accepted
    if (!fFirstBlockAccepted) return false;

    // same as !IsInitialBlockDownload() but no cs_main needed here
    int64_t nMaxBlockTime = std::max(pCurrentBlockIndex->GetBlockTime(), pindexBestHeader->GetBlockTime());
    fBlockchainSynced = pindexBestHeader->nHeight - pCurrentBlockIndex->nHeight < 24 * 6 &&
                        GetTime() - nMaxBlockTime < Params().MaxTipAge();
    return fBlockchainSynced;
}

void CZnodeSync::Fail() {
    nTimeLastFailure = GetTime();
    nRequestedZnodeAssets = ZNODE_SYNC_FAILED;
}

void CZnodeSync::Reset() {
    nRequestedZnodeAssets = ZNODE_SYNC_INITIAL;
    nRequestedZnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastZnodeList = GetTime();
    nTimeLastPaymentVote = GetTime();
    nTimeLastGovernanceItem = GetTime();
    nTimeLastFailure = 0;
    nCountFailures = 0;
}

std::string CZnodeSync::GetAssetName() {
    switch (nRequestedZnodeAssets) {
        case (ZNODE_SYNC_INITIAL):
            return "ZNODE_SYNC_INITIAL";
        case (ZNODE_SYNC_SPORKS):
            return "ZNODE_SYNC_SPORKS";
        case (ZNODE_SYNC_LIST):
            return "ZNODE_SYNC_LIST";
        case (ZNODE_SYNC_MNW):
            return "ZNODE_SYNC_MNW";
        case (ZNODE_SYNC_FAILED):
            return "ZNODE_SYNC_FAILED";
        case ZNODE_SYNC_FINISHED:
            return "ZNODE_SYNC_FINISHED";
        default:
            return "UNKNOWN";
    }
}

void CZnodeSync::SwitchToNextAsset() {
    switch (nRequestedZnodeAssets) {
        case (ZNODE_SYNC_FAILED):
            throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
            break;
        case (ZNODE_SYNC_INITIAL):
            ClearFulfilledRequests();
            nRequestedZnodeAssets = ZNODE_SYNC_SPORKS;
            LogPrintf("CZnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case (ZNODE_SYNC_SPORKS):
            nTimeLastZnodeList = GetTime();
            nRequestedZnodeAssets = ZNODE_SYNC_LIST;
            LogPrintf("CZnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case (ZNODE_SYNC_LIST):
            nTimeLastPaymentVote = GetTime();
            nRequestedZnodeAssets = ZNODE_SYNC_MNW;
            LogPrintf("CZnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;

        case (ZNODE_SYNC_MNW):
            nTimeLastGovernanceItem = GetTime();
            LogPrintf("CZnodeSync::SwitchToNextAsset -- Sync has finished\n");
            nRequestedZnodeAssets = ZNODE_SYNC_FINISHED;
            break;
    }
    nRequestedZnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
}

std::string CZnodeSync::GetSyncStatus() {
    switch (znodeSync.nRequestedZnodeAssets) {
        case ZNODE_SYNC_INITIAL:
            return _("Synchronization pending...");
        case ZNODE_SYNC_SPORKS:
            return _("Synchronizing sporks...");
        case ZNODE_SYNC_LIST:
            return _("Synchronizing znodes...");
        case ZNODE_SYNC_MNW:
            return _("Synchronizing znode payments...");
        case ZNODE_SYNC_FAILED:
            return _("Synchronization failed");
        case ZNODE_SYNC_FINISHED:
            return _("Synchronization finished");
        default:
            return "";
    }
}

void CZnodeSync::ProcessMessage(CNode *pfrom, std::string &strCommand, CDataStream &vRecv) {
    if (strCommand == NetMsgType::SYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if (IsSynced() || IsFailed()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrintf("SYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->id);
    }
}

void CZnodeSync::ClearFulfilledRequests() {
    TRY_LOCK(cs_vNodes, lockRecv);
    if (!lockRecv) return;

    BOOST_FOREACH(CNode * pnode, vNodes)
    {
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "spork-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "znode-list-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "znode-payment-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "full-sync");
    }
}

void CZnodeSync::ProcessTick() {
    static int nTick = 0;
    if (nTick++ % ZNODE_SYNC_TICK_SECONDS != 0) return;
    if (!pCurrentBlockIndex) return;

    //the actual count of znodes we have currently
    int nMnCount = mnodeman.CountZnodes();

    LogPrint("ProcessTick", "CZnodeSync::ProcessTick -- nTick %d nMnCount %d\n", nTick, nMnCount);

    // INITIAL SYNC SETUP / LOG REPORTING
    double nSyncProgress = double(nRequestedZnodeAttempt + (nRequestedZnodeAssets - 1) * 8) / (8 * 4);
    LogPrint("ProcessTick", "CZnodeSync::ProcessTick -- nTick %d nRequestedZnodeAssets %d nRequestedZnodeAttempt %d nSyncProgress %f\n", nTick, nRequestedZnodeAssets, nRequestedZnodeAttempt, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);

    // RESET SYNCING INCASE OF FAILURE
    {
        if (IsSynced()) {
            /*
                Resync if we lost all znodes from sleep/wake or failed to sync originally
            */
            if (nMnCount == 0) {
                LogPrintf("CZnodeSync::ProcessTick -- WARNING: not enough data, restarting sync\n");
                Reset();
            } else {
                std::vector < CNode * > vNodesCopy = g_connman->CopyNodeVector();
                g_connman->ReleaseNodeVector(vNodesCopy);
                return;
            }
        }

        //try syncing again
        if (IsFailed()) {
            if (nTimeLastFailure + (1 * 60) < GetTime()) { // 1 minute cooldown after failed sync
                Reset();
            }
            return;
        }
    }

    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && !IsBlockchainSynced() && nRequestedZnodeAssets > ZNODE_SYNC_SPORKS) {
        nTimeLastZnodeList = GetTime();
        nTimeLastPaymentVote = GetTime();
        nTimeLastGovernanceItem = GetTime();
        return;
    }
    if (nRequestedZnodeAssets == ZNODE_SYNC_INITIAL || (nRequestedZnodeAssets == ZNODE_SYNC_SPORKS && IsBlockchainSynced())) {
        SwitchToNextAsset();
    }

    std::vector < CNode * > vNodesCopy = g_connman->CopyNodeVector();

    BOOST_FOREACH(CNode * pnode, vNodesCopy)
    {
        // Don't try to sync any data from outbound "znode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "znode" connection
        // initialted from another node, so skip it too.
        if (pnode->fZnode || (fMasternodeMode && pnode->fInbound)) continue;

        // QUICK MODE (REGTEST ONLY!)
        if (Params().NetworkIDString() == CBaseChainParams::REGTEST) {
            if (nRequestedZnodeAttempt <= 2) {
                g_connman->PushMessage(pnode, CNetMsgMaker(LEGACY_ZNODES_PROTOCOL_VERSION).Make(NetMsgType::GETSPORKS)); //get current network sporks
            } else if (nRequestedZnodeAttempt < 4) {
                mnodeman.DsegUpdate(pnode);
            } else if (nRequestedZnodeAttempt < 6) {
                int nMnCount = mnodeman.CountZnodes();
                g_connman->PushMessage(pnode, CNetMsgMaker(LEGACY_ZNODES_PROTOCOL_VERSION).Make(NetMsgType::ZNODEPAYMENTSYNC, nMnCount)); //sync payment votes
            } else {
                nRequestedZnodeAssets = ZNODE_SYNC_FINISHED;
            }
            nRequestedZnodeAttempt++;
            g_connman->ReleaseNodeVector(vNodesCopy);
            return;
        }

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if (netfulfilledman.HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrintf("CZnodeSync::ProcessTick -- disconnecting from recently synced peer %d\n", pnode->id);
                continue;
            }

            // SPORK : ALWAYS ASK FOR SPORKS AS WE SYNC (we skip this mode now)

            if (!netfulfilledman.HasFulfilledRequest(pnode->addr, "spork-sync")) {
                // only request once from each peer
                netfulfilledman.AddFulfilledRequest(pnode->addr, "spork-sync");
                // get current network sporks
                g_connman->PushMessage(pnode, CNetMsgMaker(LEGACY_ZNODES_PROTOCOL_VERSION).Make(NetMsgType::GETSPORKS));
                LogPrintf("CZnodeSync::ProcessTick -- nTick %d nRequestedZnodeAssets %d -- requesting sporks from peer %d\n", nTick, nRequestedZnodeAssets, pnode->id);
                continue; // always get sporks first, switch to the next node without waiting for the next tick
            }

            // MNLIST : SYNC ZNODE LIST FROM OTHER CONNECTED CLIENTS

            if (nRequestedZnodeAssets == ZNODE_SYNC_LIST) {
                // check for timeout first
                if (nTimeLastZnodeList < GetTime() - ZNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CZnodeSync::ProcessTick -- nTick %d nRequestedZnodeAssets %d -- timeout\n", nTick, nRequestedZnodeAssets);
                    if (nRequestedZnodeAttempt == 0) {
                        LogPrintf("CZnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // there is no way we can continue without znode list, fail here and try later
                        Fail();
                        g_connman->ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset();
                    g_connman->ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if (netfulfilledman.HasFulfilledRequest(pnode->addr, "znode-list-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "znode-list-sync");

                if (pnode->nVersion < znpayments.GetMinZnodePaymentsProto()) continue;
                nRequestedZnodeAttempt++;

                mnodeman.DsegUpdate(pnode);

                g_connman->ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // MNW : SYNC ZNODE PAYMENT VOTES FROM OTHER CONNECTED CLIENTS

            if (nRequestedZnodeAssets == ZNODE_SYNC_MNW) {
                LogPrint("znpayments", "CZnodeSync::ProcessTick -- nTick %d nRequestedZnodeAssets %d nTimeLastPaymentVote %lld GetTime() %lld diff %lld\n", nTick, nRequestedZnodeAssets, nTimeLastPaymentVote, GetTime(), GetTime() - nTimeLastPaymentVote);
                // check for timeout first
                // This might take a lot longer than ZNODE_SYNC_TIMEOUT_SECONDS minutes due to new blocks,
                // but that should be OK and it should timeout eventually.
                if (nTimeLastPaymentVote < GetTime() - ZNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CZnodeSync::ProcessTick -- nTick %d nRequestedZnodeAssets %d -- timeout\n", nTick, nRequestedZnodeAssets);
                    if (nRequestedZnodeAttempt == 0) {
                        LogPrintf("CZnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // probably not a good idea to proceed without winner list
                        Fail();
                        g_connman->ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset();
                    g_connman->ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // check for data
                // if znpayments already has enough blocks and votes, switch to the next asset
                // try to fetch data from at least two peers though
                if (nRequestedZnodeAttempt > 1 && znpayments.IsEnoughData()) {
                    LogPrintf("CZnodeSync::ProcessTick -- nTick %d nRequestedZnodeAssets %d -- found enough data\n", nTick, nRequestedZnodeAssets);
                    SwitchToNextAsset();
                    g_connman->ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if (netfulfilledman.HasFulfilledRequest(pnode->addr, "znode-payment-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "znode-payment-sync");

                if (pnode->nVersion < znpayments.GetMinZnodePaymentsProto()) continue;
                nRequestedZnodeAttempt++;

                // ask node for all payment votes it has (new nodes will only return votes for future payments)
                g_connman->PushMessage(pnode, CNetMsgMaker(LEGACY_ZNODES_PROTOCOL_VERSION).Make(NetMsgType::ZNODEPAYMENTSYNC, znpayments.GetStorageLimit()));
                // ask node for missing pieces only (old nodes will not be asked)
                znpayments.RequestLowDataPaymentBlocks(pnode);

                g_connman->ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

        }
    }
    // looped through all nodes, release them
    g_connman->ReleaseNodeVector(vNodesCopy);
}

void CZnodeSync::UpdatedBlockTip(const CBlockIndex *pindex) {
    pCurrentBlockIndex = pindex;
}
