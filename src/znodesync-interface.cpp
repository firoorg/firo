#include "znodesync-interface.h"
#include "znode-sync.h"

#include "evo/deterministicmns.h"

CZnodeSyncInterface znodeSyncInterface;

void CZnodeSyncInterface::Reset()
{
    if (!fEvoZnodes)
        znodeSync.Reset();
    masternodeSync.Reset();
}

int CZnodeSyncInterface::GetAssetID()
{
    return fEvoZnodes ? masternodeSync.GetAssetID() : znodeSync.GetAssetID();
}

bool CZnodeSyncInterface::IsBlockchainSynced() {
    return fEvoZnodes ? masternodeSync.IsBlockchainSynced() : znodeSync.IsBlockchainSynced();
}

bool CZnodeSyncInterface::IsSynced() {
    return fEvoZnodes ? masternodeSync.IsSynced() : znodeSync.IsSynced();
}

void CZnodeSyncInterface::UpdatedBlockTip(const CBlockIndex * /*pindexNew*/, bool /*fInitialDownload*/, CConnman & /*connman*/)
{
    fEvoZnodes = deterministicMNManager->IsDIP3Enforced();
}

void CZnodeSyncInterface::SwitchToNextAsset(CConnman &connman)
{
    fEvoZnodes ? masternodeSync.SwitchToNextAsset(connman) : znodeSync.SwitchToNextAsset();
}

std::string CZnodeSyncInterface::GetAssetName()
{
    return fEvoZnodes ? masternodeSync.GetAssetName() : znodeSync.GetAssetName();
}

std::string CZnodeSyncInterface::GetSyncStatus()
{
    return fEvoZnodes ? masternodeSync.GetSyncStatus() : znodeSync.GetSyncStatus();
}