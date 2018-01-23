// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef SMARTNODE_SYNC_H
#define SMARTNODE_SYNC_H

#include "../chain.h"
#include "../net.h"

#include <univalue.h>

class CSmartnodeSync;

static const int SMARTNODE_SYNC_FAILED          = -1;
static const int SMARTNODE_SYNC_INITIAL         = 0; // sync just started, was reset recently or still in IDB
static const int SMARTNODE_SYNC_WAITING         = 1; // waiting after initial to see if we can get more headers/blocks
static const int SMARTNODE_SYNC_LIST            = 2;
static const int SMARTNODE_SYNC_MNW             = 3;
static const int SMARTNODE_SYNC_GOVERNANCE      = 4;
static const int SMARTNODE_SYNC_GOVOBJ          = 10;
static const int SMARTNODE_SYNC_GOVOBJ_VOTE     = 11;
static const int SMARTNODE_SYNC_FINISHED        = 999;

static const int SMARTNODE_SYNC_TICK_SECONDS    = 6;
static const int SMARTNODE_SYNC_TIMEOUT_SECONDS = 30; // our blocks are 2.5 minutes so 30 seconds should be fine

static const int SMARTNODE_SYNC_ENOUGH_PEERS    = 6;

extern CSmartnodeSync smartnodeSync;

//
// CSmartnodeSync : Sync smartnode assets in stages
//

class CSmartnodeSync
{
private:
    // Keep track of current asset
    int nRequestedSmartnodeAssets;
    // Count peers we've requested the asset from
    int nRequestedSmartnodeAttempt;

    // Time when current smartnode asset sync started
    int64_t nTimeAssetSyncStarted;
    // ... last bumped
    int64_t nTimeLastBumped;
    // ... or failed
    int64_t nTimeLastFailure;

    void Fail();
    void ClearFulfilledRequests(CConnman& connman);

public:
    CSmartnodeSync() { Reset(); }


    void SendGovernanceSyncRequest(CNode* pnode, CConnman& connman);

    bool IsFailed() { return nRequestedSmartnodeAssets == SMARTNODE_SYNC_FAILED; }
    bool IsBlockchainSynced() { return nRequestedSmartnodeAssets > SMARTNODE_SYNC_WAITING; }
    bool IsSmartnodeListSynced() { return nRequestedSmartnodeAssets > SMARTNODE_SYNC_LIST; }
    bool IsWinnersListSynced() { return nRequestedSmartnodeAssets > SMARTNODE_SYNC_MNW; }
    bool IsSynced() { return nRequestedSmartnodeAssets == SMARTNODE_SYNC_FINISHED; }

    int GetAssetID() { return nRequestedSmartnodeAssets; }
    int GetAttempt() { return nRequestedSmartnodeAttempt; }
    void BumpAssetLastTime(std::string strFuncName);
    int64_t GetAssetStartTime() { return nTimeAssetSyncStarted; }
    std::string GetAssetName();
    std::string GetSyncStatus();

    void Reset();
    void SwitchToNextAsset(CConnman& connman);

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    void ProcessTick(CConnman& connman);

    void AcceptedBlockHeader(const CBlockIndex *pindexNew);
    void NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman);
    void UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman);
};

#endif
