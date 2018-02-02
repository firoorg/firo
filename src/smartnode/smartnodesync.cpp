// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activesmartnode.h"
#include "checkpoints.h"
#include "validation.h"
#include "smartnode.h"
#include "smartnodepayments.h"
#include "smartnodesync.h"
#include "smartnodeman.h"
#include "netfulfilledman.h"
#include "spork.h"
#include "ui_interface.h"
#include "util.h"

class CSmartnodeSync;
CSmartnodeSync smartnodeSync;

void CSmartnodeSync::Fail()
{
    nTimeLastFailure = GetTime();
    nRequestedSmartnodeAssets = SMARTNODE_SYNC_FAILED;
}

void CSmartnodeSync::Reset()
{
    nRequestedSmartnodeAssets = SMARTNODE_SYNC_INITIAL;
    nRequestedSmartnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastBumped = GetTime();
    nTimeLastFailure = 0;
}

void CSmartnodeSync::BumpAssetLastTime(std::string strFuncName)
{
    if(IsSynced() || IsFailed()) return;
    nTimeLastBumped = GetTime();
    LogPrint("mnsync", "CSmartnodeSync::BumpAssetLastTime -- %s\n", strFuncName);
}

std::string CSmartnodeSync::GetAssetName()
{
    switch(nRequestedSmartnodeAssets)
    {
        case(SMARTNODE_SYNC_INITIAL):      return "SMARTNODE_SYNC_INITIAL";
        case(SMARTNODE_SYNC_WAITING):      return "SMARTNODE_SYNC_WAITING";
        case(SMARTNODE_SYNC_LIST):         return "SMARTNODE_SYNC_LIST";
        case(SMARTNODE_SYNC_MNW):          return "SMARTNODE_SYNC_MNW";
        case(SMARTNODE_SYNC_GOVERNANCE):   return "SMARTNODE_SYNC_GOVERNANCE";
        case(SMARTNODE_SYNC_FAILED):       return "SMARTNODE_SYNC_FAILED";
        case SMARTNODE_SYNC_FINISHED:      return "SMARTNODE_SYNC_FINISHED";
        default:                            return "UNKNOWN";
    }
}

void CSmartnodeSync::SwitchToNextAsset(CConnman& connman)
{
    switch(nRequestedSmartnodeAssets)
    {
        case(SMARTNODE_SYNC_FAILED):
            throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
            break;
        case(SMARTNODE_SYNC_INITIAL):
            ClearFulfilledRequests(connman);
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_WAITING;
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(SMARTNODE_SYNC_WAITING):
            ClearFulfilledRequests(connman);
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_LIST;
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(SMARTNODE_SYNC_LIST):
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_MNW;
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(SMARTNODE_SYNC_MNW):
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_FINISHED;
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(SMARTNODE_SYNC_GOVERNANCE):
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_FINISHED;
            uiInterface.NotifyAdditionalDataSyncProgressChanged(1);
            //try to activate our smartnode if possible
            activeSmartnode.ManageState(connman);

            // TODO: Find out whether we can just use LOCK instead of:
            // TRY_LOCK(cs_vNodes, lockRecv);
            // if(lockRecv) { ... }

            connman.ForEachNode(CConnman::AllNodes, [](CNode* pnode) {
                netfulfilledman.AddFulfilledRequest(pnode->addr, "full-sync");
            });
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Sync has finished\n");

            break;
    }
    nRequestedSmartnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    BumpAssetLastTime("CSmartnodeSync::SwitchToNextAsset");
}

std::string CSmartnodeSync::GetSyncStatus()
{
    switch (smartnodeSync.nRequestedSmartnodeAssets) {
        case SMARTNODE_SYNC_INITIAL:       return _("Synchroning blockchain...");
        case SMARTNODE_SYNC_WAITING:       return _("Synchronization pending...");
        case SMARTNODE_SYNC_LIST:          return _("Synchronizing smartnodes...");
        case SMARTNODE_SYNC_MNW:           return _("Synchronizing smartnode payments...");
        case SMARTNODE_SYNC_GOVERNANCE:    return _("Synchronizing governance objects...");
        case SMARTNODE_SYNC_FAILED:        return _("Synchronization failed");
        case SMARTNODE_SYNC_FINISHED:      return _("Synchronization finished");
        default:                            return "";
    }
}

void CSmartnodeSync::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == NetMsgType::SYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if(IsSynced() || IsFailed()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrintf("SYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->id);
    }
}

void CSmartnodeSync::ClearFulfilledRequests(CConnman& connman)
{
    // TODO: Find out whether we can just use LOCK instead of:
    // TRY_LOCK(cs_vNodes, lockRecv);
    // if(!lockRecv) return;

    connman.ForEachNode(CConnman::AllNodes, [](CNode* pnode) {
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "spork-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "smartnode-list-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "smartnode-payment-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "governance-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "full-sync");
    });
}

void CSmartnodeSync::ProcessTick(CConnman& connman)
{
    static int nTick = 0;
    if(nTick++ % SMARTNODE_SYNC_TICK_SECONDS != 0) return;

    // reset the sync process if the last call to this function was more than 60 minutes ago (client was in sleep mode)
    static int64_t nTimeLastProcess = GetTime();
    if(GetTime() - nTimeLastProcess > 60*60) {
        LogPrintf("CSmartnodeSync::HasSyncFailures -- WARNING: no actions for too long, restarting sync...\n");
        Reset();
        SwitchToNextAsset(connman);
        nTimeLastProcess = GetTime();
        return;
    }
    nTimeLastProcess = GetTime();

    // reset sync status in case of any other sync failure
    if(IsFailed()) {
        if(nTimeLastFailure + (1*60) < GetTime()) { // 1 minute cooldown after failed sync
            LogPrintf("CSmartnodeSync::HasSyncFailures -- WARNING: failed to sync, trying again...\n");
            Reset();
            SwitchToNextAsset(connman);
        }
        return;
    }

    // gradually request the rest of the votes after sync finished
    if(IsSynced()) {
        std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();
        //governance.RequestGovernanceObjectVotes(vNodesCopy, connman);
        connman.ReleaseNodeVector(vNodesCopy);
        return;
    }

    // Calculate "progress" for LOG reporting / GUI notification
    double nSyncProgress = double(nRequestedSmartnodeAttempt + (nRequestedSmartnodeAssets - 1) * 8) / (8*4);
    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d nRequestedSmartnodeAttempt %d nSyncProgress %f\n", nTick, nRequestedSmartnodeAssets, nRequestedSmartnodeAttempt, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);

    std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();

    BOOST_FOREACH(CNode* pnode, vNodesCopy)
    {
        // Don't try to sync any data from outbound "smartnode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "smartnode" connection
        // initiated from another node, so skip it too.
        if(pnode->fSmartnode || (fSmartNode && pnode->fInbound)) continue;

        // QUICK MODE (REGTEST ONLY!)
        if(Params().NetworkIDString() == CBaseChainParams::REGTEST)
        {
            if(nRequestedSmartnodeAttempt <= 2) {
                connman.PushMessageWithVersion(pnode, INIT_PROTO_VERSION, NetMsgType::GETSPORKS); //get current network sporks
            } else if(nRequestedSmartnodeAttempt < 4) {
                mnodeman.DsegUpdate(pnode, connman);
            } else if(nRequestedSmartnodeAttempt < 6) {
                int nMnCount = mnodeman.CountSmartnodes();
                connman.PushMessage(pnode, NetMsgType::SMARTNODEPAYMENTSYNC, nMnCount); //sync payment votes
                SendGovernanceSyncRequest(pnode, connman);
            } else {
                nRequestedSmartnodeAssets = SMARTNODE_SYNC_FINISHED;
            }
            nRequestedSmartnodeAttempt++;
            connman.ReleaseNodeVector(vNodesCopy);
            return;
        }

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if(netfulfilledman.HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrintf("CSmartnodeSync::ProcessTick -- disconnecting from recently synced peer %d\n", pnode->id);
                continue;
            }

            // SPORK : ALWAYS ASK FOR SPORKS AS WE SYNC

            if(!netfulfilledman.HasFulfilledRequest(pnode->addr, "spork-sync")) {
                // always get sporks first, only request once from each peer
                netfulfilledman.AddFulfilledRequest(pnode->addr, "spork-sync");
                // get current network sporks
                connman.PushMessageWithVersion(pnode, INIT_PROTO_VERSION, NetMsgType::GETSPORKS);
                LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- requesting sporks from peer %d\n", nTick, nRequestedSmartnodeAssets, pnode->id);
            }

            // INITIAL TIMEOUT

            if(nRequestedSmartnodeAssets == SMARTNODE_SYNC_WAITING) {
                if(GetTime() - nTimeLastBumped > SMARTNODE_SYNC_TIMEOUT_SECONDS) {
                    // At this point we know that:
                    // a) there are peers (because we are looping on at least one of them);
                    // b) we waited for at least SMARTNODE_SYNC_TIMEOUT_SECONDS since we reached
                    //    the headers tip the last time (i.e. since we switched from
                    //     SMARTNODE_SYNC_INITIAL to SMARTNODE_SYNC_WAITING and bumped time);
                    // c) there were no blocks (UpdatedBlockTip, NotifyHeaderTip) or headers (AcceptedBlockHeader)
                    //    for at least SMARTNODE_SYNC_TIMEOUT_SECONDS.
                    // We must be at the tip already, let's move to the next asset.
                    SwitchToNextAsset(connman);
                }
            }

            // MNLIST : SYNC SMARTNODE LIST FROM OTHER CONNECTED CLIENTS

            if(nRequestedSmartnodeAssets == SMARTNODE_SYNC_LIST) {
                LogPrint("smartnode", "CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedSmartnodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                if(GetTime() - nTimeLastBumped > SMARTNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- timeout\n", nTick, nRequestedSmartnodeAssets);
                    if (nRequestedSmartnodeAttempt == 0) {
                        LogPrintf("CSmartnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // there is no way we can continue without smartnode list, fail here and try later
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "smartnode-list-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "smartnode-list-sync");

                if (pnode->nVersion < mnpayments.GetMinSmartnodePaymentsProto()) continue;
                nRequestedSmartnodeAttempt++;

                mnodeman.DsegUpdate(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // MNW : SYNC SMARTNODE PAYMENT VOTES FROM OTHER CONNECTED CLIENTS

            if(nRequestedSmartnodeAssets == SMARTNODE_SYNC_MNW) {
                LogPrint("mnpayments", "CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedSmartnodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                // This might take a lot longer than SMARTNODE_SYNC_TIMEOUT_SECONDS due to new blocks,
                // but that should be OK and it should timeout eventually.
                if(GetTime() - nTimeLastBumped > SMARTNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- timeout\n", nTick, nRequestedSmartnodeAssets);
                    if (nRequestedSmartnodeAttempt == 0) {
                        LogPrintf("CSmartnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // probably not a good idea to proceed without winner list
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // check for data
                // if mnpayments already has enough blocks and votes, switch to the next asset
                // try to fetch data from at least two peers though
                if(nRequestedSmartnodeAttempt > 1 && mnpayments.IsEnoughData()) {
                    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- found enough data\n", nTick, nRequestedSmartnodeAssets);
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "smartnode-payment-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "smartnode-payment-sync");

                if(pnode->nVersion < mnpayments.GetMinSmartnodePaymentsProto()) continue;
                nRequestedSmartnodeAttempt++;

                // ask node for all payment votes it has (new nodes will only return votes for future payments)
                connman.PushMessage(pnode, NetMsgType::SMARTNODEPAYMENTSYNC, mnpayments.GetStorageLimit());
                // ask node for missing pieces only (old nodes will not be asked)
                mnpayments.RequestLowDataPaymentBlocks(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // GOVOBJ : SYNC GOVERNANCE ITEMS FROM OUR PEERS

            // if(nRequestedSmartnodeAssets == SMARTNODE_SYNC_GOVERNANCE) {
            //     LogPrint("gobject", "CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedSmartnodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);

            //     // check for timeout first
            //     if(GetTime() - nTimeLastBumped > SMARTNODE_SYNC_TIMEOUT_SECONDS) {
            //         LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- timeout\n", nTick, nRequestedSmartnodeAssets);
            //         if(nRequestedSmartnodeAttempt == 0) {
            //             LogPrintf("CSmartnodeSync::ProcessTick -- WARNING: failed to sync %s\n", GetAssetName());
            //             // it's kind of ok to skip this for now, hopefully we'll catch up later?
            //         }
            //         SwitchToNextAsset(connman);
            //         connman.ReleaseNodeVector(vNodesCopy);
            //         return;
            //     }

            //     // only request obj sync once from each peer, then request votes on per-obj basis
            //     if(netfulfilledman.HasFulfilledRequest(pnode->addr, "governance-sync")) {
            //         int nObjsLeftToAsk = governance.RequestGovernanceObjectVotes(pnode, connman);
            //         static int64_t nTimeNoObjectsLeft = 0;
            //         // check for data
            //         if(nObjsLeftToAsk == 0) {
            //             static int nLastTick = 0;
            //             static int nLastVotes = 0;
            //             if(nTimeNoObjectsLeft == 0) {
            //                 // asked all objects for votes for the first time
            //                 nTimeNoObjectsLeft = GetTime();
            //             }
            //             // make sure the condition below is checked only once per tick
            //             if(nLastTick == nTick) continue;
            //             if(GetTime() - nTimeNoObjectsLeft > SMARTNODE_SYNC_TIMEOUT_SECONDS &&
            //                 governance.GetVoteCount() - nLastVotes < std::max(int(0.0001 * nLastVotes), SMARTNODE_SYNC_TICK_SECONDS)
            //             ) {
            //                 // We already asked for all objects, waited for SMARTNODE_SYNC_TIMEOUT_SECONDS
            //                 // after that and less then 0.01% or SMARTNODE_SYNC_TICK_SECONDS
            //                 // (i.e. 1 per second) votes were recieved during the last tick.
            //                 // We can be pretty sure that we are done syncing.
            //                 LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- asked for all objects, nothing to do\n", nTick, nRequestedSmartnodeAssets);
            //                 // reset nTimeNoObjectsLeft to be able to use the same condition on resync
            //                 nTimeNoObjectsLeft = 0;
            //                 SwitchToNextAsset(connman);
            //                 connman.ReleaseNodeVector(vNodesCopy);
            //                 return;
            //             }
            //             nLastTick = nTick;
            //             nLastVotes = governance.GetVoteCount();
            //         }
            //         continue;
            //     }
            //     netfulfilledman.AddFulfilledRequest(pnode->addr, "governance-sync");

            //     if (pnode->nVersion < MIN_GOVERNANCE_PEER_PROTO_VERSION) continue;
            //     nRequestedSmartnodeAttempt++;

            //     SendGovernanceSyncRequest(pnode, connman);

            //     connman.ReleaseNodeVector(vNodesCopy);
            //     return; //this will cause each peer to get one request each six seconds for the various assets we need
            // }
        }
    }
    // looped through all nodes, release them
    connman.ReleaseNodeVector(vNodesCopy);
}

void CSmartnodeSync::SendGovernanceSyncRequest(CNode* pnode, CConnman& connman)
{
    // if(pnode->nVersion >= GOVERNANCE_FILTER_PROTO_VERSION) {
    //     CBloomFilter filter;
    //     filter.clear();

    //     connman.PushMessage(pnode, NetMsgType::MNGOVERNANCESYNC, uint256(), filter);
    // }
    // else {
    //     connman.PushMessage(pnode, NetMsgType::MNGOVERNANCESYNC, uint256());
    // }
}

void CSmartnodeSync::AcceptedBlockHeader(const CBlockIndex *pindexNew)
{
    LogPrint("mnsync", "CSmartnodeSync::AcceptedBlockHeader -- pindexNew->nHeight: %d\n", pindexNew->nHeight);

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block header arrives while we are still syncing blockchain
        BumpAssetLastTime("CSmartnodeSync::AcceptedBlockHeader");
    }
}

void CSmartnodeSync::NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint("mnsync", "CSmartnodeSync::NotifyHeaderTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CSmartnodeSync::NotifyHeaderTip");
    }
}

void CSmartnodeSync::UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint("mnsync", "CSmartnodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CSmartnodeSync::UpdatedBlockTip");
    }

    if (fInitialDownload) {
        // switched too early
        if (IsBlockchainSynced()) {
            Reset();
        }

        // no need to check any further while still in IBD mode
        return;
    }

    // Note: since we sync headers first, it should be ok to use this
    static bool fReachedBestHeader = false;
    bool fReachedBestHeaderNew = pindexNew->GetBlockHash() == pindexBestHeader->GetBlockHash();

    if (fReachedBestHeader && !fReachedBestHeaderNew) {
        // Switching from true to false means that we previousely stuck syncing headers for some reason,
        // probably initial timeout was not enough,
        // because there is no way we can update tip not having best header
        Reset();
        fReachedBestHeader = false;
        return;
    }

    fReachedBestHeader = fReachedBestHeaderNew;

    LogPrint("mnsync", "CSmartnodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d pindexBestHeader->nHeight: %d fInitialDownload=%d fReachedBestHeader=%d\n",
                pindexNew->nHeight, pindexBestHeader->nHeight, fInitialDownload, fReachedBestHeader);

    if (!IsBlockchainSynced() && fReachedBestHeader) {
        // Reached best header while being in initial mode.
        // We must be at the tip already, let's move to the next asset.
        SwitchToNextAsset(connman);
    }
}
