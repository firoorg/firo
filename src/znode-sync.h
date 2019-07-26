// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ZNODE_SYNC_H
#define ZNODE_SYNC_H

#include "chain.h"
#include "net.h"

#include <univalue.h>
#include <atomic>

class CZnodeSync;

static const int ZNODE_SYNC_FAILED          = -1;
static const int ZNODE_SYNC_INITIAL         = 0;
static const int ZNODE_SYNC_SPORKS          = 1;
static const int ZNODE_SYNC_LIST            = 2;
static const int ZNODE_SYNC_MNW             = 3;
static const int ZNODE_SYNC_FINISHED        = 999;

static const int ZNODE_SYNC_TICK_SECONDS    = 6;
static const int ZNODE_SYNC_TIMEOUT_SECONDS = 30; // our blocks are 2.5 minutes so 30 seconds should be fine

static const int ZNODE_SYNC_ENOUGH_PEERS    = 3;

extern CZnodeSync znodeSync;

//
// CZnodeSync : Sync znode assets in stages
//

class CZnodeSync
{
private:
    // Keep track of current asset
    int nRequestedZnodeAssets;
    // Count peers we've requested the asset from
    int nRequestedZnodeAttempt;

    // Time when current znode asset sync started
    int64_t nTimeAssetSyncStarted;

    // Last time when we received some znode asset ...
    int64_t nTimeLastZnodeList;
    int64_t nTimeLastPaymentVote;
    int64_t nTimeLastGovernanceItem;
    // ... or failed
    int64_t nTimeLastFailure;

    // How many times we failed
    int nCountFailures;

    // Keep track of current block index
    std::atomic<const CBlockIndex *> pCurrentBlockIndex;

    bool CheckNodeHeight(CNode* pnode, bool fDisconnectStuckNodes = false);
    void Fail();
    void ClearFulfilledRequests();

public:
    CZnodeSync() { Reset(); }

    void AddedZnodeList() { nTimeLastZnodeList = GetTime(); }
    void AddedPaymentVote() { nTimeLastPaymentVote = GetTime(); }
    void AddedGovernanceItem() { nTimeLastGovernanceItem = GetTime(); };

    void SendGovernanceSyncRequest(CNode* pnode);

    bool IsFailed() { return nRequestedZnodeAssets == ZNODE_SYNC_FAILED; }
    bool IsBlockchainSynced(bool fBlockAccepted = false);
    bool IsZnodeListSynced() { return nRequestedZnodeAssets > ZNODE_SYNC_LIST; }
    bool IsWinnersListSynced() { return nRequestedZnodeAssets > ZNODE_SYNC_MNW; }
    bool IsSynced() { return nRequestedZnodeAssets == ZNODE_SYNC_FINISHED; }

    int GetAssetID() { return nRequestedZnodeAssets; }
    int GetAttempt() { return nRequestedZnodeAttempt; }
    std::string GetAssetName();
    std::string GetSyncStatus();

    void Reset();
    void SwitchToNextAsset();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    void ProcessTick();

    void UpdatedBlockTip(const CBlockIndex *pindex);
};

#endif
