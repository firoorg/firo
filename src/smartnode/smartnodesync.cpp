// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activesmartnode.h"
#include "checkpoints.h"
#include "main.h"
#include "smartnode.h"
#include "smartnodepayments.h"
#include "smartnodesync.h"
#include "smartnodeman.h"
#include "netfulfilledman.h"
#include "spork.h"
#include "util.h"

class CSmartnodeSync;

CSmartnodeSync smartnodeSync;

bool CSmartnodeSync::CheckNodeHeight(CNode *pnode, bool fDisconnectStuckNodes) {
    CNodeStateStats stats;
    if (!GetNodeStateStats(pnode->id, stats) || stats.nCommonHeight == -1 || stats.nSyncHeight == -1) return false; // not enough info about this peer

    // Check blocks and headers, allow a small error margin of 1 block
    if (pCurrentBlockIndex->nHeight - 1 > stats.nCommonHeight) {
        // This peer probably stuck, don't sync any additional data from it
        if (fDisconnectStuckNodes) {
            // Disconnect to free this connection slot for another peer.
            pnode->fDisconnect = true;
            LogPrintf("CSmartnodeSync::CheckNodeHeight -- disconnecting from stuck peer, nHeight=%d, nCommonHeight=%d, peer=%d\n",
                      pCurrentBlockIndex->nHeight, stats.nCommonHeight, pnode->id);
        } else {
            LogPrintf("CSmartnodeSync::CheckNodeHeight -- skipping stuck peer, nHeight=%d, nCommonHeight=%d, peer=%d\n",
                      pCurrentBlockIndex->nHeight, stats.nCommonHeight, pnode->id);
        }
        return false;
    } else if (pCurrentBlockIndex->nHeight < stats.nSyncHeight - 1) {
        // This peer announced more headers than we have blocks currently
        LogPrintf("CSmartnodeSync::CheckNodeHeight -- skipping peer, who announced more headers than we have blocks currently, nHeight=%d, nSyncHeight=%d, peer=%d\n",
                  pCurrentBlockIndex->nHeight, stats.nSyncHeight, pnode->id);
        return false;
    }

    return true;
}

bool CSmartnodeSync::IsBlockchainSynced(bool fBlockAccepted) {
    static bool fBlockchainSynced = false;
    static int64_t nTimeLastProcess = GetTime();
    static int nSkipped = 0;
    static bool fFirstBlockAccepted = false;

    // if the last call to this function was more than 60 minutes ago (client was in sleep mode) reset the sync process
    if (GetTime() - nTimeLastProcess > 60 * 60) {
        LogPrintf("CSmartnodeSync::IsBlockchainSynced time-check fBlockchainSynced=%s\n", fBlockchainSynced);
        Reset();
        fBlockchainSynced = false;
    }

    if (!pCurrentBlockIndex || !pindexBestHeader || fImporting || fReindex) return false;

    if (fBlockAccepted) {
        // this should be only triggered while we are still syncing
        if (!IsSynced()) {
            // we are trying to download smth, reset blockchain sync status
            LogPrintf("CSmartnodeSync::IsBlockchainSynced -- reset\n");
            fFirstBlockAccepted = true;
            fBlockchainSynced = false;
            nTimeLastProcess = GetTime();
            return false;
        }
    } else {
        // skip if we already checked less than 1 tick ago
        if (GetTime() - nTimeLastProcess < SMARTNODE_SYNC_TICK_SECONDS) {
            nSkipped++;
            return fBlockchainSynced;
        }
    }

    if (fDebug) LogPrintf("CSmartnodeSync::IsBlockchainSynced -- state before check: %ssynced, skipped %d times\n", fBlockchainSynced ? "" : "not ", nSkipped);

    nTimeLastProcess = GetTime();
    nSkipped = 0;

    if (fBlockchainSynced){
        return true;
    }

    if (fCheckpointsEnabled && pCurrentBlockIndex->nHeight < Checkpoints::GetTotalBlocksEstimate(Params().Checkpoints())) {
        return false;
    }

    std::vector < CNode * > vNodesCopy = CopyNodeVector();
    LogPrintf("vNodesCopy.size() = %s\n", vNodesCopy.size());
    LogPrintf("SMARTNODE_SYNC_ENOUGH_PEERS = %s\n", SMARTNODE_SYNC_ENOUGH_PEERS);
    // We have enough peers and assume most of them are synced
    if (vNodesCopy.size() >= SMARTNODE_SYNC_ENOUGH_PEERS) {
        // Check to see how many of our peers are (almost) at the same height as we are
        int nNodesAtSameHeight = 0;
        BOOST_FOREACH(CNode * pnode, vNodesCopy)
        {
            // Make sure this peer is presumably at the same height
            if (!CheckNodeHeight(pnode)) {
                continue;
            }
            nNodesAtSameHeight++;
            LogPrintf("nNodesAtSameHeight=%s\n", nNodesAtSameHeight);
            // if we have decent number of such peers, most likely we are synced now
            if (nNodesAtSameHeight >= SMARTNODE_SYNC_ENOUGH_PEERS) {
                LogPrintf("CSmartnodeSync::IsBlockchainSynced -- found enough peers on the same height as we are, done\n");
                fBlockchainSynced = true;
                ReleaseNodeVector(vNodesCopy);
                return true;
            }
        }
    }
    ReleaseNodeVector(vNodesCopy);

    // wait for at least one new block to be accepted
    if (!fFirstBlockAccepted) return false;

    // same as !IsInitialBlockDownload() but no cs_main needed here
    int64_t nMaxBlockTime = std::max(pCurrentBlockIndex->GetBlockTime(), pindexBestHeader->GetBlockTime());
    fBlockchainSynced = pindexBestHeader->nHeight - pCurrentBlockIndex->nHeight < 24 * 6 &&
                        GetTime() - nMaxBlockTime < Params().MaxTipAge();
    return fBlockchainSynced;
}

void CSmartnodeSync::Fail() {
    nTimeLastFailure = GetTime();
    nRequestedSmartnodeAssets = SMARTNODE_SYNC_FAILED;
}

void CSmartnodeSync::Reset() {
    nRequestedSmartnodeAssets = SMARTNODE_SYNC_INITIAL;
    nRequestedSmartnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastSmartnodeList = GetTime();
    nTimeLastPaymentVote = GetTime();
    nTimeLastGovernanceItem = GetTime();
    nTimeLastFailure = 0;
    nCountFailures = 0;
}

std::string CSmartnodeSync::GetAssetName() {
    switch (nRequestedSmartnodeAssets) {
        case (SMARTNODE_SYNC_INITIAL):
            return "SMARTNODE_SYNC_INITIAL";
        case (SMARTNODE_SYNC_SPORKS):
            return "SMARTNODE_SYNC_SPORKS";
        case (SMARTNODE_SYNC_LIST):
            return "SMARTNODE_SYNC_LIST";
        case (SMARTNODE_SYNC_MNW):
            return "SMARTNODE_SYNC_MNW";
        case (SMARTNODE_SYNC_FAILED):
            return "SMARTNODE_SYNC_FAILED";
        case SMARTNODE_SYNC_FINISHED:
            return "SMARTNODE_SYNC_FINISHED";
        default:
            return "UNKNOWN";
    }
}

void CSmartnodeSync::SwitchToNextAsset() {
    switch (nRequestedSmartnodeAssets) {
        case (SMARTNODE_SYNC_FAILED):
            throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
            break;
        case (SMARTNODE_SYNC_INITIAL):
            ClearFulfilledRequests();
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_SPORKS;
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case (SMARTNODE_SYNC_SPORKS):
            nTimeLastSmartnodeList = GetTime();
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_LIST;
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case (SMARTNODE_SYNC_LIST):
            nTimeLastPaymentVote = GetTime();
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_MNW;
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;

        case (SMARTNODE_SYNC_MNW):
            nTimeLastGovernanceItem = GetTime();
            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Sync has finished\n");
            nRequestedSmartnodeAssets = SMARTNODE_SYNC_FINISHED;
//            break;
//        case (SMARTNODE_SYNC_GOVERNANCE):
//            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Sync has finished\n");
//            nRequestedSmartnodeAssets = SMARTNODE_SYNC_FINISHED;
//
//        case (SMARTNODE_SYNC_MNW):
//            nTimeLastGovernanceItem = GetTime();
//            nRequestedSmartnodeAssets = SMARTNODE_SYNC_GOVERNANCE;
//            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
//            break;
//        case (SMARTNODE_SYNC_GOVERNANCE):
//            LogPrintf("CSmartnodeSync::SwitchToNextAsset -- Sync has finished\n");
//            nRequestedSmartnodeAssets = SMARTNODE_SYNC_FINISHED;
//            uiInterface.NotifyAdditionalDataSyncProgressChanged(1);
            //try to activate our smartnode if possible
            activeSmartnode.ManageState();

            TRY_LOCK(cs_vNodes, lockRecv);
            if (!lockRecv) return;

            BOOST_FOREACH(CNode * pnode, vNodes)
            {
                netfulfilledman.AddFulfilledRequest(pnode->addr, "full-sync");
            }

            break;
    }
    nRequestedSmartnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
}

std::string CSmartnodeSync::GetSyncStatus() {
    switch (smartnodeSync.nRequestedSmartnodeAssets) {
        case SMARTNODE_SYNC_INITIAL:
            return _("Synchronization pending...");
        case SMARTNODE_SYNC_SPORKS:
            return _("Synchronizing sporks...");
        case SMARTNODE_SYNC_LIST:
            return _("Synchronizing smartnodes...");
        case SMARTNODE_SYNC_MNW:
            return _("Synchronizing smartnode payments...");
        case SMARTNODE_SYNC_FAILED:
            return _("Synchronization failed");
        case SMARTNODE_SYNC_FINISHED:
            return _("Synchronization finished");
        default:
            return "";
    }
}

void CSmartnodeSync::ProcessMessage(CNode *pfrom, std::string &strCommand, CDataStream &vRecv) {
    if (strCommand == NetMsgType::SYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if (IsSynced() || IsFailed()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrintf("SYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->id);
    }
}

void CSmartnodeSync::ClearFulfilledRequests() {
    TRY_LOCK(cs_vNodes, lockRecv);
    if (!lockRecv) return;

    BOOST_FOREACH(CNode * pnode, vNodes)
    {
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "spork-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "smartnode-list-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "smartnode-payment-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "full-sync");
    }
}

void CSmartnodeSync::ProcessTick() {
    static int nTick = 0;
    if (nTick++ % SMARTNODE_SYNC_TICK_SECONDS != 0) return;
    if (!pCurrentBlockIndex) return;

    //the actual count of smartnodes we have currently
    int nMnCount = mnodeman.CountSmartnodes();

    if (fDebug) LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nMnCount %d\n", nTick, nMnCount);

    // RESET SYNCING INCASE OF FAILURE
    {
        if (IsSynced()) {
            /*
                Resync if we lost all smartnodes from sleep/wake or failed to sync originally
            */
            if (nMnCount == 0) {
                LogPrintf("CSmartnodeSync::ProcessTick -- WARNING: not enough data, restarting sync\n");
                Reset();
            } else {
                std::vector < CNode * > vNodesCopy = CopyNodeVector();
//                governance.RequestGovernanceObjectVotes(vNodesCopy);
                ReleaseNodeVector(vNodesCopy);
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

    // INITIAL SYNC SETUP / LOG REPORTING
    double nSyncProgress = double(nRequestedSmartnodeAttempt + (nRequestedSmartnodeAssets - 1) * 8) / (8 * 4);
    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d nRequestedSmartnodeAttempt %d nSyncProgress %f\n", nTick, nRequestedSmartnodeAssets, nRequestedSmartnodeAttempt, nSyncProgress);
//    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);

    LogPrintf("sporks synced but blockchain is not, wait until we're almost at a recent block to continue\n");
    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && !IsBlockchainSynced() && nRequestedSmartnodeAssets > SMARTNODE_SYNC_SPORKS) {
        nTimeLastSmartnodeList = GetTime();
        nTimeLastPaymentVote = GetTime();
        nTimeLastGovernanceItem = GetTime();
        return;
    }
    if (nRequestedSmartnodeAssets == SMARTNODE_SYNC_INITIAL || (nRequestedSmartnodeAssets == SMARTNODE_SYNC_SPORKS && IsBlockchainSynced())) {
        SwitchToNextAsset();
    }

    std::vector < CNode * > vNodesCopy = CopyNodeVector();

    BOOST_FOREACH(CNode * pnode, vNodesCopy)
    {
        // Don't try to sync any data from outbound "smartnode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "smartnode" connection
        // initialted from another node, so skip it too.
        if (pnode->fSmartnode || (fSmartNode && pnode->fInbound)) continue;

        // QUICK MODE (REGTEST ONLY!)
        if (Params().NetworkIDString() == CBaseChainParams::REGTEST) {
            if (nRequestedSmartnodeAttempt <= 2) {
                pnode->PushMessage(NetMsgType::GETSPORKS); //get current network sporks
            } else if (nRequestedSmartnodeAttempt < 4) {
                mnodeman.DsegUpdate(pnode);
            } else if (nRequestedSmartnodeAttempt < 6) {
                int nMnCount = mnodeman.CountSmartnodes();
                pnode->PushMessage(NetMsgType::SMARTNODEPAYMENTSYNC, nMnCount); //sync payment votes
            } else {
                nRequestedSmartnodeAssets = SMARTNODE_SYNC_FINISHED;
            }
            nRequestedSmartnodeAttempt++;
            ReleaseNodeVector(vNodesCopy);
            return;
        }

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if (netfulfilledman.HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrintf("CSmartnodeSync::ProcessTick -- disconnecting from recently synced peer %d\n", pnode->id);
                continue;
            }

            // SPORK : ALWAYS ASK FOR SPORKS AS WE SYNC (we skip this mode now)

            if (!netfulfilledman.HasFulfilledRequest(pnode->addr, "spork-sync")) {
                // only request once from each peer
                netfulfilledman.AddFulfilledRequest(pnode->addr, "spork-sync");
                // get current network sporks
                pnode->PushMessage(NetMsgType::GETSPORKS);
                LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- requesting sporks from peer %d\n", nTick, nRequestedSmartnodeAssets, pnode->id);
                continue; // always get sporks first, switch to the next node without waiting for the next tick
            }

            // MNLIST : SYNC SMARTNODE LIST FROM OTHER CONNECTED CLIENTS

            if (nRequestedSmartnodeAssets == SMARTNODE_SYNC_LIST) {
                // check for timeout first
                if (nTimeLastSmartnodeList < GetTime() - SMARTNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- timeout\n", nTick, nRequestedSmartnodeAssets);
                    if (nRequestedSmartnodeAttempt == 0) {
                        LogPrintf("CSmartnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // there is no way we can continue without smartnode list, fail here and try later
                        Fail();
                        ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset();
                    ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if (netfulfilledman.HasFulfilledRequest(pnode->addr, "smartnode-list-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "smartnode-list-sync");

                if (pnode->nVersion < mnpayments.GetMinSmartnodePaymentsProto()) continue;
                nRequestedSmartnodeAttempt++;

                mnodeman.DsegUpdate(pnode);

                ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // MNW : SYNC SMARTNODE PAYMENT VOTES FROM OTHER CONNECTED CLIENTS

            if (nRequestedSmartnodeAssets == SMARTNODE_SYNC_MNW) {
                LogPrint("mnpayments", "CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d nTimeLastPaymentVote %lld GetTime() %lld diff %lld\n", nTick, nRequestedSmartnodeAssets, nTimeLastPaymentVote, GetTime(), GetTime() - nTimeLastPaymentVote);
                // check for timeout first
                // This might take a lot longer than SMARTNODE_SYNC_TIMEOUT_SECONDS minutes due to new blocks,
                // but that should be OK and it should timeout eventually.
                if (nTimeLastPaymentVote < GetTime() - SMARTNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- timeout\n", nTick, nRequestedSmartnodeAssets);
                    if (nRequestedSmartnodeAttempt == 0) {
                        LogPrintf("CSmartnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // probably not a good idea to proceed without winner list
                        Fail();
                        ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset();
                    ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // check for data
                // if mnpayments already has enough blocks and votes, switch to the next asset
                // try to fetch data from at least two peers though
                if (nRequestedSmartnodeAttempt > 1 && mnpayments.IsEnoughData()) {
                    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- found enough data\n", nTick, nRequestedSmartnodeAssets);
                    SwitchToNextAsset();
                    ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if (netfulfilledman.HasFulfilledRequest(pnode->addr, "smartnode-payment-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "smartnode-payment-sync");

                if (pnode->nVersion < mnpayments.GetMinSmartnodePaymentsProto()) continue;
                nRequestedSmartnodeAttempt++;

                // ask node for all payment votes it has (new nodes will only return votes for future payments)
                pnode->PushMessage(NetMsgType::SMARTNODEPAYMENTSYNC, mnpayments.GetStorageLimit());
                // ask node for missing pieces only (old nodes will not be asked)
                mnpayments.RequestLowDataPaymentBlocks(pnode);

                ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // GOVOBJ : SYNC GOVERNANCE ITEMS FROM OUR PEERS

//            if (nRequestedSmartnodeAssets == SMARTNODE_SYNC_GOVERNANCE) {
//                LogPrint("gobject", "CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d nTimeLastGovernanceItem %lld GetTime() %lld diff %lld\n", nTick, nRequestedSmartnodeAssets, nTimeLastGovernanceItem, GetTime(), GetTime() - nTimeLastGovernanceItem);
//
//                // check for timeout first
//                if (GetTime() - nTimeLastGovernanceItem > SMARTNODE_SYNC_TIMEOUT_SECONDS) {
//                    LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- timeout\n", nTick, nRequestedSmartnodeAssets);
//                    if (nRequestedSmartnodeAttempt == 0) {
//                        LogPrintf("CSmartnodeSync::ProcessTick -- WARNING: failed to sync %s\n", GetAssetName());
//                        // it's kind of ok to skip this for now, hopefully we'll catch up later?
//                    }
//                    SwitchToNextAsset();
//                    ReleaseNodeVector(vNodesCopy);
//                    return;
//                }

                // only request obj sync once from each peer, then request votes on per-obj basis
//                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "governance-sync")) {
//                    int nObjsLeftToAsk = governance.RequestGovernanceObjectVotes(pnode);
//                    int nObjsLeftToAsk = governance.RequestGovernanceObjectVotes(pnode);
//                    static int64_t nTimeNoObjectsLeft = 0;
//                    // check for data
//                    if(nObjsLeftToAsk == 0) {
//                        static int nLastTick = 0;
//                        static int nLastVotes = 0;
//                        if(nTimeNoObjectsLeft == 0) {
//                            // asked all objects for votes for the first time
//                            nTimeNoObjectsLeft = GetTime();
//                        }
//                        // make sure the condition below is checked only once per tick
//                        if(nLastTick == nTick) continue;
//                        if(GetTime() - nTimeNoObjectsLeft > SMARTNODE_SYNC_TIMEOUT_SECONDS &&
//                            governance.GetVoteCount() - nLastVotes < std::max(int(0.0001 * nLastVotes), SMARTNODE_SYNC_TICK_SECONDS)
//                        ) {
//                            // We already asked for all objects, waited for SMARTNODE_SYNC_TIMEOUT_SECONDS
//                            // after that and less then 0.01% or SMARTNODE_SYNC_TICK_SECONDS
//                            // (i.e. 1 per second) votes were recieved during the last tick.
//                            // We can be pretty sure that we are done syncing.
//                            LogPrintf("CSmartnodeSync::ProcessTick -- nTick %d nRequestedSmartnodeAssets %d -- asked for all objects, nothing to do\n", nTick, nRequestedSmartnodeAssets);
//                            // reset nTimeNoObjectsLeft to be able to use the same condition on resync
//                            nTimeNoObjectsLeft = 0;
//                            SwitchToNextAsset();
//                            ReleaseNodeVector(vNodesCopy);
//                            return;
//                        }
//                        nLastTick = nTick;
//                        nLastVotes = governance.GetVoteCount();
//                    }
//                    continue;
//                }
//                netfulfilledman.AddFulfilledRequest(pnode->addr, "governance-sync");

//                if (pnode->nVersion < MIN_GOVERNANCE_PEER_PROTO_VERSION) continue;
//                nRequestedSmartnodeAttempt++;

//                SendGovernanceSyncRequest(pnode);

//                ReleaseNodeVector(vNodesCopy);
//                return; //this will cause each peer to get one request each six seconds for the various assets we need
//            }
        }
    }
    // looped through all nodes, release them
    ReleaseNodeVector(vNodesCopy);
}

//void CSmartnodeSync::SendGovernanceSyncRequest(CNode *pnode) {
//    if(pnode->nVersion >= GOVERNANCE_FILTER_PROTO_VERSION) {
//        CBloomFilter filter;
//        filter.clear();
//
//        pnode->PushMessage(NetMsgType::MNGOVERNANCESYNC, uint256(), filter);
//    }
//    else {
//        pnode->PushMessage(NetMsgType::MNGOVERNANCESYNC, uint256());
//    }
//}

void CSmartnodeSync::UpdatedBlockTip(const CBlockIndex *pindex) {
    pCurrentBlockIndex = pindex;
}
