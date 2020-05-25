// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONINTERFACE_H
#define BITCOIN_VALIDATIONINTERFACE_H

#include <boost/signals2/signal.hpp>
#include <boost/shared_ptr.hpp>
#include <memory>
#include "primitives/transaction.h"

class CBlock;
class CBlockIndex;
struct CBlockLocator;
class CBlockIndex;
class CConnman;
class CReserveScript;
class CTransaction;
class CValidationInterface;
class CValidationState;
class CGovernanceVote;
class CGovernanceObject;
class CDeterministicMN;
class CDeterministicMNList;
class CDeterministicMNListDiff;
class uint256;
class CZnode;

typedef std::shared_ptr<CDeterministicMN> CDeterministicMNPtr;

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();

class CValidationInterface {
protected:
    virtual void WalletTransaction(const CTransaction& tx) {}
    virtual void AcceptedBlockHeader(const CBlockIndex *pindexNew) {}
    virtual void NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload) {}
    virtual void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) {}
    virtual void SyncTransaction(const CTransaction &tx, const CBlockIndex *pindex, int posInBlock) {}
    virtual void NotifyTransactionLock(const CTransaction &tx) {}
    virtual void NotifyChainLock(const CBlockIndex* pindex) {}
    virtual void NotifyGovernanceVote(const CGovernanceVote &vote) {}
    virtual void NotifyGovernanceObject(const CGovernanceObject &object) {}
    virtual void NotifyInstantSendDoubleSpendAttempt(const CTransaction &currentTx, const CTransaction &previousTx) {}
    virtual void NotifyMasternodeListChanged(bool undo, const CDeterministicMNList& oldMNList, const CDeterministicMNListDiff& diff) {}
    virtual void SetBestChain(const CBlockLocator &locator) {}
    virtual bool UpdatedTransaction(const uint256 &hash) { return false; }
    virtual void Inventory(const uint256 &hash) {}
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman) {}
    virtual void BlockChecked(const CBlock&, const CValidationState&) {}
    virtual void GetScriptForMining(boost::shared_ptr<CReserveScript>&) {};
    virtual void ResetRequestCount(const uint256 &hash) {};
    virtual void NumConnectionsChanged() {}
    virtual void UpdateSyncStatus() {}
    virtual void UpdatedZnode(CZnode &znode) {}
    virtual void UpdatedMasternode(CDeterministicMNPtr masternode) {};
    virtual void UpdatedMintStatus(std::string update) {};
    virtual void UpdatedSettings(std::string update) {};
    virtual void NotifyAPIStatus() {}
    virtual void NotifyZnodeList() {}
    virtual void UpdatedBalance() {}
    virtual void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& block) {};
    virtual void WalletSegment(const std::string &) {}
    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

struct CMainSignals {
    /** Notifies listeners of accepted block header */
    boost::signals2::signal<void (const CBlockIndex *)> AcceptedBlockHeader;
    /** Notifies listeners of updated block header tip */
    boost::signals2::signal<void (const CBlockIndex *, bool fInitialDownload)> NotifyHeaderTip;
    /** Notifies listeners of updated block chain tip */
    boost::signals2::signal<void (const CBlockIndex *, const CBlockIndex *, bool fInitialDownload)> UpdatedBlockTip;
    /** A posInBlock value for SyncTransaction calls for tranactions not
     * included in connected blocks such as transactions removed from mempool,
     * accepted to mempool or appearing in disconnected blocks.*/
    static const int SYNC_TRANSACTION_NOT_IN_BLOCK = -1;
    boost::signals2::signal<void (const CTransaction &, const CBlockIndex *pindex, int posInBlock)> SyncTransaction;    
    /** Notifies listeners of updated transaction data (transaction, and
     * optionally the block it is found in). Called with block data when
     * transaction is included in a connected block, and without block data when
     * transaction was accepted to mempool, removed from mempool (only when
     * removal was due to conflict from connected block), or appeared in a
     * disconnected block.*/

    /** Notifies listeners of a valid wallet transaction (decoupled from SyncTransaction in order to allow wallet update). */
    boost::signals2::signal<void (const CTransaction &)> WalletTransaction;
    /** Notifies listeners of an updated transaction lock without new data. */
    boost::signals2::signal<void (const CTransaction &)> NotifyTransactionLock;
    /** Notifies listeners of a ChainLock. */
    boost::signals2::signal<void (const CBlockIndex* pindex)> NotifyChainLock;
    /** Notifies listeners of a new governance vote. */
    boost::signals2::signal<void (const CGovernanceVote &)> NotifyGovernanceVote;
    /** Notifies listeners of a new governance object. */
    boost::signals2::signal<void (const CGovernanceObject &)> NotifyGovernanceObject;
    /** Notifies listeners of a attempted InstantSend double spend*/
    boost::signals2::signal<void(const CTransaction &currentTx, const CTransaction &previousTx)> NotifyInstantSendDoubleSpendAttempt;
    /** Notifies listeners that the MN list changed */
    boost::signals2::signal<void(bool undo, const CDeterministicMNList& oldMNList, const CDeterministicMNListDiff& diff)> NotifyMasternodeListChanged;
    /** Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible). */
    boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
    /** Notifies listeners of a new active block chain. */
    boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
    /** Notifies listeners about an inventory item being seen on the network. */
    boost::signals2::signal<void (const uint256 &)> Inventory;
    /** Tells listeners to broadcast their data. */
    boost::signals2::signal<void (int64_t nBestBlockTime, CConnman* connman)> Broadcast;
    /** Notifies listeners of a block validation result */
    boost::signals2::signal<void (const CBlock&, const CValidationState&)> BlockChecked;
    /** Notifies listeners that a key for mining is required (coinbase) */
    boost::signals2::signal<void (boost::shared_ptr<CReserveScript>&)> ScriptForMining;
    /** Notifies listeners that a block has been successfully mined */
    boost::signals2::signal<void (const uint256 &)> BlockFound;
    /** Notifies listeners of change in number of active connections */
    boost::signals2::signal<void ()> NumConnectionsChanged;
    /** Notifies listeners of change of blockchain syncing state */
    boost::signals2::signal<void ()> UpdateSyncStatus;
    /** Notifies listeners of change to a Znode entry */
    boost::signals2::signal<void (CZnode &)> UpdatedZnode;
    /** Notifies listeners of change to a Masternode entry */
    boost::signals2::signal<void (CDeterministicMNPtr)> UpdatedMasternode;
    /** Notifies listeners of an updated mint status */
    boost::signals2::signal<void (std::string)> UpdatedMintStatus;
    /** Notifies listeners of settings following an update */
    boost::signals2::signal<void (std::string)> UpdatedSettings;
    /** Notifies listeners of API status */
    boost::signals2::signal<void ()> NotifyAPIStatus;
    /** Notifies listeners of Znode list */
    boost::signals2::signal<void ()> NotifyZnodeList;
    /** Notifies listeners of balance */
    boost::signals2::signal<void ()> UpdatedBalance;
    /**
     * Notifies listeners that a block which builds directly on our current tip
     * has been received and connected to the headers tree, though not validated yet */
    boost::signals2::signal<void (const CBlockIndex *, const std::shared_ptr<const CBlock>&)> NewPoWValidBlock;
    /** Notifies listeners of wallet segment (stateWallet) */
    boost::signals2::signal<void (const std::string &)> WalletSegment;
};

CMainSignals& GetMainSignals();

#endif // BITCOIN_VALIDATIONINTERFACE_H
