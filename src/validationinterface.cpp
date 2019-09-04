// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validationinterface.h"
#include "util.h"

static CMainSignals g_signals;

CMainSignals& GetMainSignals()
{
    return g_signals;
}

void RegisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.UpdatedBlockTip.connect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1));
    g_signals.SyncTransaction.connect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.UpdatedTransaction.connect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.SetBestChain.connect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1));
    g_signals.BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.ScriptForMining.connect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.BlockFound.connect(boost::bind(&CValidationInterface::ResetRequestCount, pwalletIn, _1));
    g_signals.NumConnectionsChanged.connect(boost::bind(&CValidationInterface::NumConnectionsChanged, pwalletIn));
    g_signals.UpdateSyncStatus.connect(boost::bind(&CValidationInterface::UpdateSyncStatus, pwalletIn));
    g_signals.UpdatedZnode.connect(boost::bind(&CValidationInterface::UpdatedZnode, pwalletIn, _1));
    g_signals.UpdatedMintStatus.connect(boost::bind(&CValidationInterface::UpdatedMintStatus, pwalletIn, _1));
    g_signals.UpdatedSettings.connect(boost::bind(&CValidationInterface::UpdatedSettings, pwalletIn, _1));
    g_signals.NotifyAPIStatus.connect(boost::bind(&CValidationInterface::NotifyAPIStatus, pwalletIn));
    g_signals.UpdatedBalance.connect(boost::bind(&CValidationInterface::UpdatedBalance, pwalletIn));
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.BlockFound.disconnect(boost::bind(&CValidationInterface::ResetRequestCount, pwalletIn, _1));
    g_signals.ScriptForMining.disconnect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1));
    g_signals.Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.SetBestChain.disconnect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.UpdatedTransaction.disconnect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.SyncTransaction.disconnect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.UpdatedBlockTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1));
    g_signals.NumConnectionsChanged.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn));
    g_signals.UpdateSyncStatus.disconnect(boost::bind(&CValidationInterface::UpdateSyncStatus, pwalletIn));
    g_signals.UpdatedZnode.disconnect(boost::bind(&CValidationInterface::UpdatedZnode, pwalletIn, _1));
    g_signals.UpdatedMintStatus.disconnect(boost::bind(&CValidationInterface::UpdatedMintStatus, pwalletIn, _1));
    g_signals.UpdatedSettings.disconnect(boost::bind(&CValidationInterface::UpdatedSettings, pwalletIn, _1));
    g_signals.NotifyAPIStatus.disconnect(boost::bind(&CValidationInterface::NotifyAPIStatus, pwalletIn));
    g_signals.UpdatedBalance.disconnect(boost::bind(&CValidationInterface::UpdatedBalance, pwalletIn));
}

void UnregisterAllValidationInterfaces() {
    g_signals.BlockFound.disconnect_all_slots();
    g_signals.ScriptForMining.disconnect_all_slots();
    g_signals.BlockChecked.disconnect_all_slots();
    g_signals.Broadcast.disconnect_all_slots();
    g_signals.Inventory.disconnect_all_slots();
    g_signals.SetBestChain.disconnect_all_slots();
    g_signals.UpdatedTransaction.disconnect_all_slots();
    g_signals.SyncTransaction.disconnect_all_slots();
    g_signals.UpdatedBlockTip.disconnect_all_slots();
    g_signals.NumConnectionsChanged.disconnect_all_slots();
    g_signals.UpdateSyncStatus.disconnect_all_slots();
    g_signals.UpdatedZnode.disconnect_all_slots();
    g_signals.UpdatedMintStatus.disconnect_all_slots();
    g_signals.UpdatedSettings.disconnect_all_slots();
    g_signals.NotifyAPIStatus.disconnect_all_slots();
    g_signals.UpdatedBalance.disconnect_all_slots();
}

void SyncWithWallets(const CTransaction &tx, const CBlockIndex *pindex, const CBlock *pblock) {
    g_signals.SyncTransaction(tx, pindex, pblock);
}
