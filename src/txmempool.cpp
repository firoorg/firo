// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txmempool.h"

#include "clientversion.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "validation.h"
#include "policy/policy.h"
#include "policy/fees.h"
#include "streams.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utiltime.h"
#include "version.h"

#include "evo/specialtx.h"
#include "evo/providertx.h"
#include "evo/deterministicmns.h"
#include "llmq/quorums_instantsend.h"

CTxMemPoolEntry::CTxMemPoolEntry(const CTransactionRef& _tx, const CAmount& _nFee,
                                 int64_t _nTime, unsigned int _entryHeight,
                                 CAmount _inChainInputValue,
                                 bool _spendsCoinbase, int64_t _sigOpsCost, LockPoints lp):
    tx(_tx), nFee(_nFee), nTime(_nTime), entryHeight(_entryHeight),
    inChainInputValue(_inChainInputValue),
    spendsCoinbase(_spendsCoinbase), sigOpCost(_sigOpsCost), lockPoints(lp)
{
    nTxWeight = GetTransactionWeight(*tx);
    nModSize = tx->CalculateModifiedSize(GetTxSize());
    nUsageSize = RecursiveDynamicUsage(*tx) + memusage::DynamicUsage(tx);

    nCountWithDescendants = 1;
    nSizeWithDescendants = GetTxSize();
    nModFeesWithDescendants = nFee;
    CAmount nValueIn = tx->GetValueOut()+nFee;
    if (!tx->HasNoRegularInputs()) {
        assert(inChainInputValue <= nValueIn);
    }

    feeDelta = 0;

    nCountWithAncestors = 1;
    nSizeWithAncestors = GetTxSize();
    nModFeesWithAncestors = nFee;
    nSigOpCostWithAncestors = sigOpCost;
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTxMemPoolEntry& other)
{
    *this = other;
}

void CTxMemPoolEntry::UpdateFeeDelta(int64_t newFeeDelta)
{
    nModFeesWithDescendants += newFeeDelta - feeDelta;
    nModFeesWithAncestors += newFeeDelta - feeDelta;
    feeDelta = newFeeDelta;
}

void CTxMemPoolEntry::UpdateLockPoints(const LockPoints& lp)
{
    lockPoints = lp;
}

size_t CTxMemPoolEntry::GetTxSize() const
{
    return GetVirtualTransactionSize(nTxWeight, sigOpCost);
}

// Update the given tx for any in-mempool descendants.
// Assumes that setMemPoolChildren is correct for the given tx and all
// descendants.
void CTxMemPool::UpdateForDescendants(txiter updateIt, cacheMap &cachedDescendants, const std::set<uint256> &setExclude)
{
    setEntries stageEntries, setAllDescendants;
    stageEntries = GetMemPoolChildren(updateIt);

    while (!stageEntries.empty()) {
        const txiter cit = *stageEntries.begin();
        setAllDescendants.insert(cit);
        stageEntries.erase(cit);
        const setEntries &setChildren = GetMemPoolChildren(cit);
        BOOST_FOREACH(const txiter childEntry, setChildren) {
            cacheMap::iterator cacheIt = cachedDescendants.find(childEntry);
            if (cacheIt != cachedDescendants.end()) {
                // We've already calculated this one, just add the entries for this set
                // but don't traverse again.
                BOOST_FOREACH(const txiter cacheEntry, cacheIt->second) {
                    setAllDescendants.insert(cacheEntry);
                }
            } else if (!setAllDescendants.count(childEntry)) {
                // Schedule for later processing
                stageEntries.insert(childEntry);
            }
        }
    }
    // setAllDescendants now contains all in-mempool descendants of updateIt.
    // Update and add to cached descendant map
    int64_t modifySize = 0;
    CAmount modifyFee = 0;
    int64_t modifyCount = 0;
    BOOST_FOREACH(txiter cit, setAllDescendants) {
        if (!setExclude.count(cit->GetTx().GetHash())) {
            modifySize += cit->GetTxSize();
            modifyFee += cit->GetModifiedFee();
            modifyCount++;
            cachedDescendants[updateIt].insert(cit);
            // Update ancestor state for each descendant
            mapTx.modify(cit, update_ancestor_state(updateIt->GetTxSize(), updateIt->GetModifiedFee(), 1, updateIt->GetSigOpCost()));
        }
    }
    mapTx.modify(updateIt, update_descendant_state(modifySize, modifyFee, modifyCount));
}

// vHashesToUpdate is the set of transaction hashes from a disconnected block
// which has been re-added to the mempool.
// for each entry, look for descendants that are outside hashesToUpdate, and
// add fee/size information for such descendants to the parent.
// for each such descendant, also update the ancestor state to include the parent.
void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<uint256> &vHashesToUpdate)
{
    LOCK(cs);
    // For each entry in vHashesToUpdate, store the set of in-mempool, but not
    // in-vHashesToUpdate transactions, so that we don't have to recalculate
    // descendants when we come across a previously seen entry.
    cacheMap mapMemPoolDescendantsToUpdate;

    // Use a set for lookups into vHashesToUpdate (these entries are already
    // accounted for in the state of their ancestors)
    std::set<uint256> setAlreadyIncluded(vHashesToUpdate.begin(), vHashesToUpdate.end());

    // Iterate in reverse, so that whenever we are looking at at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    // This maximizes the benefit of the descendant cache and guarantees that
    // setMemPoolChildren will be updated, an assumption made in
    // UpdateForDescendants.
    BOOST_REVERSE_FOREACH(const uint256 &hash, vHashesToUpdate) {
        // we cache the in-mempool children to avoid duplicate updates
        setEntries setChildren;
        // calculate children from mapNextTx
        txiter it = mapTx.find(hash);
        if (it == mapTx.end()) {
            continue;
        }
        auto iter = mapNextTx.lower_bound(COutPoint(hash, 0));
        // First calculate the children, and update setMemPoolChildren to
        // include them, and update their setMemPoolParents to include this tx.
        for (; iter != mapNextTx.end() && iter->first->hash == hash; ++iter) {
            const uint256 &childHash = iter->second->GetHash();
            txiter childIter = mapTx.find(childHash);
            assert(childIter != mapTx.end());
            // We can skip updating entries we've encountered before or that
            // are in the block (which are already accounted for).
            if (setChildren.insert(childIter).second && !setAlreadyIncluded.count(childHash)) {
                UpdateChild(it, childIter, true);
                UpdateParent(childIter, it, true);
            }
        }
        UpdateForDescendants(it, mapMemPoolDescendantsToUpdate, setAlreadyIncluded);
    }
}

bool CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, setEntries &setAncestors, uint64_t limitAncestorCount, uint64_t limitAncestorSize, uint64_t limitDescendantCount, uint64_t limitDescendantSize, std::string &errString, bool fSearchForParents /* = true */) const
{
    LOCK(cs);

    setEntries parentHashes;
    const CTransaction &tx = entry.GetTx();

    if (fSearchForParents) {
        // Get parents of this transaction that are in the mempool
        // GetMemPoolParents() is only valid for entries in the mempool, so we
        // iterate mapTx to find parents.
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            txiter piter = mapTx.find(tx.vin[i].prevout.hash);
            if (piter != mapTx.end()) {
                parentHashes.insert(piter);
                if (parentHashes.size() + 1 > limitAncestorCount) {
                    errString = strprintf("too many unconfirmed parents [limit: %u]", limitAncestorCount);
                    return false;
                }
            }
        }
    } else {
        // If we're not searching for parents, we require this to be an
        // entry in the mempool already.
        txiter it = mapTx.iterator_to(entry);
        parentHashes = GetMemPoolParents(it);
    }

    size_t totalSizeWithAncestors = entry.GetTxSize();

    while (!parentHashes.empty()) {
        txiter stageit = *parentHashes.begin();

        setAncestors.insert(stageit);
        parentHashes.erase(stageit);
        totalSizeWithAncestors += stageit->GetTxSize();

        if (stageit->GetSizeWithDescendants() + entry.GetTxSize() > limitDescendantSize) {
            errString = strprintf("exceeds descendant size limit for tx %s [limit: %u]", stageit->GetTx().GetHash().ToString(), limitDescendantSize);
            return false;
        } else if (stageit->GetCountWithDescendants() + 1 > limitDescendantCount) {
            errString = strprintf("too many descendants for tx %s [limit: %u]", stageit->GetTx().GetHash().ToString(), limitDescendantCount);
            return false;
        } else if (totalSizeWithAncestors > limitAncestorSize) {
            errString = strprintf("exceeds ancestor size limit [limit: %u]", limitAncestorSize);
            return false;
        }

        const setEntries & setMemPoolParents = GetMemPoolParents(stageit);
        BOOST_FOREACH(const txiter &phash, setMemPoolParents) {
            // If this is a new ancestor, add it.
            if (setAncestors.count(phash) == 0) {
                parentHashes.insert(phash);
            }
            if (parentHashes.size() + setAncestors.size() + 1 > limitAncestorCount) {
                errString = strprintf("too many unconfirmed ancestors [limit: %u]", limitAncestorCount);
                return false;
            }
        }
    }

    return true;
}

void CTxMemPool::UpdateAncestorsOf(bool add, txiter it, setEntries &setAncestors)
{
    setEntries parentIters = GetMemPoolParents(it);
    // add or remove this tx as a child of each parent
    BOOST_FOREACH(txiter piter, parentIters) {
        UpdateChild(piter, it, add);
    }
    const int64_t updateCount = (add ? 1 : -1);
    const int64_t updateSize = updateCount * it->GetTxSize();
    const CAmount updateFee = updateCount * it->GetModifiedFee();
    BOOST_FOREACH(txiter ancestorIt, setAncestors) {
        mapTx.modify(ancestorIt, update_descendant_state(updateSize, updateFee, updateCount));
    }
}

void CTxMemPool::UpdateEntryForAncestors(txiter it, const setEntries &setAncestors)
{
    int64_t updateCount = setAncestors.size();
    int64_t updateSize = 0;
    CAmount updateFee = 0;
    int64_t updateSigOpsCost = 0;
    BOOST_FOREACH(txiter ancestorIt, setAncestors) {
        updateSize += ancestorIt->GetTxSize();
        updateFee += ancestorIt->GetModifiedFee();
        updateSigOpsCost += ancestorIt->GetSigOpCost();
    }
    mapTx.modify(it, update_ancestor_state(updateSize, updateFee, updateCount, updateSigOpsCost));
}

void CTxMemPool::UpdateChildrenForRemoval(txiter it)
{
    const setEntries &setMemPoolChildren = GetMemPoolChildren(it);
    BOOST_FOREACH(txiter updateIt, setMemPoolChildren) {
        UpdateParent(updateIt, it, false);
    }
}

void CTxMemPool::UpdateForRemoveFromMempool(const setEntries &entriesToRemove, bool updateDescendants)
{
    // For each entry, walk back all ancestors and decrement size associated with this
    // transaction
    const uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    if (updateDescendants) {
        // updateDescendants should be true whenever we're not recursively
        // removing a tx and all its descendants, eg when a transaction is
        // confirmed in a block.
        // Here we only update statistics and not data in mapLinks (which
        // we need to preserve until we're finished with all operations that
        // need to traverse the mempool).
        BOOST_FOREACH(txiter removeIt, entriesToRemove) {
            setEntries setDescendants;
            CalculateDescendants(removeIt, setDescendants);
            setDescendants.erase(removeIt); // don't update state for self
            int64_t modifySize = -((int64_t)removeIt->GetTxSize());
            CAmount modifyFee = -removeIt->GetModifiedFee();
            int modifySigOps = -removeIt->GetSigOpCost();
            BOOST_FOREACH(txiter dit, setDescendants) {
                mapTx.modify(dit, update_ancestor_state(modifySize, modifyFee, -1, modifySigOps));
            }
        }
    }
    BOOST_FOREACH(txiter removeIt, entriesToRemove) {
        setEntries setAncestors;
        const CTxMemPoolEntry &entry = *removeIt;
        std::string dummy;
        // Since this is a tx that is already in the mempool, we can call CMPA
        // with fSearchForParents = false.  If the mempool is in a consistent
        // state, then using true or false should both be correct, though false
        // should be a bit faster.
        // However, if we happen to be in the middle of processing a reorg, then
        // the mempool can be in an inconsistent state.  In this case, the set
        // of ancestors reachable via mapLinks will be the same as the set of
        // ancestors whose packages include this transaction, because when we
        // add a new transaction to the mempool in addUnchecked(), we assume it
        // has no children, and in the case of a reorg where that assumption is
        // false, the in-mempool children aren't linked to the in-block tx's
        // until UpdateTransactionsFromBlock() is called.
        // So if we're being called during a reorg, ie before
        // UpdateTransactionsFromBlock() has been called, then mapLinks[] will
        // differ from the set of mempool parents we'd calculate by searching,
        // and it's important that we use the mapLinks[] notion of ancestor
        // transactions as the set of things to update for removal.
        CalculateMemPoolAncestors(entry, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
        // Note that UpdateAncestorsOf severs the child links that point to
        // removeIt in the entries for the parents of removeIt.
        UpdateAncestorsOf(false, removeIt, setAncestors);
    }
    // After updating all the ancestor sizes, we can now sever the link between each
    // transaction being removed and any mempool children (ie, update setMemPoolParents
    // for each direct child of a transaction being removed).
    BOOST_FOREACH(txiter removeIt, entriesToRemove) {
        UpdateChildrenForRemoval(removeIt);
    }
}

void CTxMemPoolEntry::UpdateDescendantState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount)
{
    nSizeWithDescendants += modifySize;
    assert(int64_t(nSizeWithDescendants) > 0);
    nModFeesWithDescendants += modifyFee;
    nCountWithDescendants += modifyCount;
    assert(int64_t(nCountWithDescendants) > 0);
}

void CTxMemPoolEntry::UpdateAncestorState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount, int modifySigOps)
{
    nSizeWithAncestors += modifySize;
    assert(int64_t(nSizeWithAncestors) > 0);
    nModFeesWithAncestors += modifyFee;
    nCountWithAncestors += modifyCount;
    assert(int64_t(nCountWithAncestors) > 0);
    nSigOpCostWithAncestors += modifySigOps;
    assert(int(nSigOpCostWithAncestors) >= 0);
}

CTxMemPool::CTxMemPool(const CFeeRate& _minReasonableRelayFee) :
    nTransactionsUpdated(0)
{
    _clear(); //lock free clear

    // Sanity checks off by default for performance, because otherwise
    // accepting transactions becomes O(N^2) where N is the number
    // of transactions in the pool
    nCheckFrequency = 0;

    minerPolicyEstimator = new CBlockPolicyEstimator(_minReasonableRelayFee);
}

CTxMemPool::~CTxMemPool()
{
    delete minerPolicyEstimator;
}

bool CTxMemPool::isSpent(const COutPoint& outpoint)
{
    LOCK(cs);
    return mapNextTx.count(outpoint);
}

void CTxMemPool::getTransactions(std::set<uint256>& setTxid)
{
    LOCK(cs);
    for (indexed_transaction_set::const_iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi){
        setTxid.insert((*mi).GetTx().GetHash());
    }
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    LOCK(cs);
    nTransactionsUpdated += n;
}

bool CTxMemPool::addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, setEntries &setAncestors, bool validFeeEstimate)
{
    NotifyEntryAdded(entry.GetSharedTx());
    // Add to memory pool without checking anything.
    // Used by AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    LOCK(cs);
    indexed_transaction_set::iterator newit = mapTx.insert(entry).first;
    mapLinks.insert(make_pair(newit, TxLinks()));

    // Update transaction for any feeDelta created by PrioritiseTransaction
    // TODO: refactor so that the fee delta is calculated before inserting
    // into mapTx.
    std::map<uint256, std::pair<double, CAmount> >::const_iterator pos = mapDeltas.find(hash);
    if (pos != mapDeltas.end()) {
        const std::pair<double, CAmount> &deltas = pos->second;
        if (deltas.second) {
            mapTx.modify(newit, update_fee_delta(deltas.second));
        }
    }

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction& tx = newit->GetTx();
    std::set<uint256> setParentTransactions;
    if (!entry.GetTx().HasPrivateInputs()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            mapNextTx.insert(std::make_pair(&tx.vin[i].prevout, &tx));
            setParentTransactions.insert(tx.vin[i].prevout.hash);
        }
    }
    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will call UpdateTransactionsFromBlock
    // to clean up the mess we're leaving here.

    // Update ancestors with information about this tx
    BOOST_FOREACH (const uint256 &phash, setParentTransactions) {
        txiter pit = mapTx.find(phash);
        if (pit != mapTx.end()) {
            UpdateParent(newit, pit, true);
        }
    }

    UpdateAncestorsOf(true, newit, setAncestors);
    UpdateEntryForAncestors(newit, setAncestors);

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    minerPolicyEstimator->processTransaction(entry, validFeeEstimate);

    vTxHashes.emplace_back(tx.GetWitnessHash(), newit);
    newit->vTxHashesIdx = vTxHashes.size() - 1;

    // Invalid ProTxes should never get this far because transactions should be
    // fully checked by AcceptToMemoryPool() at this point, so we just assume that
    // everything is fine here.
    if (tx.nType == TRANSACTION_PROVIDER_REGISTER) {
        CProRegTx proTx;
        bool ok = GetTxPayload(tx, proTx);
        assert(ok);
        if (!proTx.collateralOutpoint.hash.IsNull()) {
            mapProTxRefs.emplace(tx.GetHash(), proTx.collateralOutpoint.hash);
        }
        mapProTxAddresses.emplace(proTx.addr, tx.GetHash());
        mapProTxPubKeyIDs.emplace(proTx.keyIDOwner, tx.GetHash());
        mapProTxBlsPubKeyHashes.emplace(proTx.pubKeyOperator.GetHash(), tx.GetHash());
        if (!proTx.collateralOutpoint.hash.IsNull()) {
            mapProTxCollaterals.emplace(proTx.collateralOutpoint, tx.GetHash());
        }
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_SERVICE) {
        CProUpServTx proTx;
        bool ok = GetTxPayload(tx, proTx);
        assert(ok);
        mapProTxRefs.emplace(proTx.proTxHash, tx.GetHash());
        mapProTxAddresses.emplace(proTx.addr, tx.GetHash());
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REGISTRAR) {
        CProUpRegTx proTx;
        bool ok = GetTxPayload(tx, proTx);
        assert(ok);
        mapProTxRefs.emplace(proTx.proTxHash, tx.GetHash());
        mapProTxBlsPubKeyHashes.emplace(proTx.pubKeyOperator.GetHash(), tx.GetHash());
        auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(proTx.proTxHash);
        assert(dmn);
        newit->validForProTxKey = ::SerializeHash(dmn->pdmnState->pubKeyOperator);
        if (dmn->pdmnState->pubKeyOperator.Get() != proTx.pubKeyOperator) {
            newit->isKeyChangeProTx = true;
        }
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REVOKE) {
        CProUpRevTx proTx;
        bool ok = GetTxPayload(tx, proTx);
        assert(ok);
        mapProTxRefs.emplace(proTx.proTxHash, tx.GetHash());
        auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(proTx.proTxHash);
        assert(dmn);
        newit->validForProTxKey = ::SerializeHash(dmn->pdmnState->pubKeyOperator);
        if (dmn->pdmnState->pubKeyOperator.Get() != CBLSPublicKey()) {
            newit->isKeyChangeProTx = true;
        }
    } else if (tx.nType == TRANSACTION_SPORK) {
        sporkManager.AcceptSporkToMemoryPool(tx);

        // evict all the transactions disabled by sporks
        std::set<uint256> evictList;
        for (txiter mi = mapTx.begin(); mi != mapTx.end(); ++mi) {
            CValidationState state;
            if (!sporkManager.IsTransactionAllowed(mi->GetTx(), state))
                evictList.insert(mi->GetTx().GetHash());
        }

        for (uint256 evictTxHash: evictList) {
            txiter txit = mapTx.find(evictTxHash);
            if (txit != mapTx.end())
                removeRecursive(txit->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }

    return true;
}

void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason)
{
    NotifyEntryRemoved(it->GetSharedTx(), reason);
    const uint256 hash = it->GetTx().GetHash();
    if (!it->GetTx().HasPrivateInputs()) {
        LogPrintf("removeUnchecked txHash=%s, IsSpend()=%s\n", hash.ToString(), it->GetTx().HasPrivateInputs());
        BOOST_FOREACH(const CTxIn& txin, it->GetTx().vin)
            mapNextTx.erase(txin.prevout);
    }
    if (vTxHashes.size() > 1) {
        vTxHashes[it->vTxHashesIdx] = std::move(vTxHashes.back());
        vTxHashes[it->vTxHashesIdx].second->vTxHashesIdx = it->vTxHashesIdx;
        vTxHashes.pop_back();
        if (vTxHashes.size() * 2 < vTxHashes.capacity())
            vTxHashes.shrink_to_fit();
    } else
        vTxHashes.clear();

    auto eraseProTxRef = [&](const uint256& proTxHash, const uint256& txHash) {
        auto its = mapProTxRefs.equal_range(proTxHash);
        for (auto it = its.first; it != its.second;) {
            if (it->second == txHash) {
                it = mapProTxRefs.erase(it);
            } else {
                ++it;
            }
        }
    };

    if (it->GetTx().nType == TRANSACTION_PROVIDER_REGISTER) {
        CProRegTx proTx;
        if (!GetTxPayload(it->GetTx(), proTx)) {
            assert(false);
        }
        if (!proTx.collateralOutpoint.IsNull()) {
            eraseProTxRef(it->GetTx().GetHash(), proTx.collateralOutpoint.hash);
        }
        mapProTxAddresses.erase(proTx.addr);
        mapProTxPubKeyIDs.erase(proTx.keyIDOwner);
        mapProTxBlsPubKeyHashes.erase(proTx.pubKeyOperator.GetHash());
        mapProTxCollaterals.erase(proTx.collateralOutpoint);
    } else if (it->GetTx().nType == TRANSACTION_PROVIDER_UPDATE_SERVICE) {
        CProUpServTx proTx;
        if (!GetTxPayload(it->GetTx(), proTx)) {
            assert(false);
        }
        eraseProTxRef(proTx.proTxHash, it->GetTx().GetHash());
        mapProTxAddresses.erase(proTx.addr);
    } else if (it->GetTx().nType == TRANSACTION_PROVIDER_UPDATE_REGISTRAR) {
        CProUpRegTx proTx;
        if (!GetTxPayload(it->GetTx(), proTx)) {
            assert(false);
        }
        eraseProTxRef(proTx.proTxHash, it->GetTx().GetHash());
        mapProTxBlsPubKeyHashes.erase(proTx.pubKeyOperator.GetHash());
    } else if (it->GetTx().nType == TRANSACTION_PROVIDER_UPDATE_REVOKE) {
        CProUpRevTx proTx;
        if (!GetTxPayload(it->GetTx(), proTx)) {
            assert(false);
        }
        eraseProTxRef(proTx.proTxHash, it->GetTx().GetHash());
    } else if (it->GetTx().nType == TRANSACTION_SPORK) {
        sporkManager.RemovedFromMemoryPool(it->GetTx());
    }

    else if (it->GetTx().IsLelantusTransaction()) {
        // Remove mints and spend serials from lelantus mempool state
        const CTransaction &tx = it->GetTx();
        if (tx.IsLelantusJoinSplit()) {
            std::vector<Scalar> serials;
            try {
                serials = lelantus::GetLelantusJoinSplitSerialNumbers(tx, tx.vin[0]);
                for (const Scalar &serial: serials)
                    lelantusState.RemoveSpendFromMempool(serial);
            }
            catch (CBadTxIn&) {
            }
        }

        BOOST_FOREACH(const CTxOut &txout, tx.vout)
        {
            if (txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint()) {
                GroupElement pubCoinValue;
                try {
                    if (txout.scriptPubKey.IsLelantusMint()) {
                        lelantus::ParseLelantusMintScript(txout.scriptPubKey, pubCoinValue);
                    } else {
                        std::vector<unsigned char> encryptedValue;
                        lelantus::ParseLelantusJMintScript(txout.scriptPubKey, pubCoinValue, encryptedValue);
                    }
                    lelantusState.RemoveMintFromMempool(pubCoinValue);
                }
                catch (std::invalid_argument&) {
                }
            }
        }
    }

    else if (it->GetTx().IsSparkTransaction()) {
        // Remove mints and spends from spark mempool state
        const CTransaction &tx = it->GetTx();
        if (tx.IsSparkSpend()) {
            std::vector<GroupElement> lTags;
            try {
                lTags = spark::GetSparkUsedTags(tx);
                for (const auto& lTag : lTags)
                    sparkState.RemoveSpendFromMempool(lTag);
            }
            catch (CBadTxIn&) {
            }

            // remove all the spark name transactions referencing this tx
            for (auto it = sparkNames.begin(); it!=sparkNames.end();) {
                if (it->second.second == tx.GetHash()) {
                    it = sparkNames.erase(it);
                } else {
                    ++it;
                }
            }
        }

        BOOST_FOREACH(const CTxOut &txout, tx.vout)
        {
            if (txout.scriptPubKey.IsSparkMint() || txout.scriptPubKey.IsSparkSMint()) {
                try {
                    const spark::Params* params = spark::Params::get_default();

                    spark::Coin txCoin(params);
                    spark::ParseSparkMintCoin(txout.scriptPubKey, txCoin);
                    sparkState.RemoveMintFromMempool(txCoin);
                }
                catch (std::invalid_argument&) {
                }
            }
        }
    }

    totalTxSize -= it->GetTxSize();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    cachedInnerUsage -= memusage::DynamicUsage(mapLinks[it].parents) + memusage::DynamicUsage(mapLinks[it].children);
    mapLinks.erase(it);
    mapTx.erase(it);
    nTransactionsUpdated++;
    minerPolicyEstimator->removeTx(hash);
}

void CTxMemPool::addAddressIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view)
{
    LOCK(cs);
    const CTransaction& tx = entry.GetTx();
    std::vector<CMempoolAddressDeltaKey> inserted;

    uint256 txhash = tx.GetHash();
    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        const CTxIn input = tx.vin[j];
        if (tx.HasPrivateInputs()) {
            continue;
        }

        const CTxOut &prevout = view.AccessCoin(input.prevout).out;
        if (prevout.scriptPubKey.IsPayToScriptHash()) {
            std::vector<unsigned char> hashBytes(prevout.scriptPubKey.begin()+2, prevout.scriptPubKey.begin()+22);
            CMempoolAddressDeltaKey key(AddressType::payToScriptHash, uint160(hashBytes), txhash, j, 1);
            CMempoolAddressDelta delta(entry.GetTime(), prevout.nValue * -1, input.prevout.hash, input.prevout.n);
            mapAddress.insert(std::make_pair(key, delta));
            inserted.push_back(key);
        } else if (prevout.scriptPubKey.IsPayToPublicKeyHash()) {
            std::vector<unsigned char> hashBytes(prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23);
            CMempoolAddressDeltaKey key(AddressType::payToPubKeyHash, uint160(hashBytes), txhash, j, 1);
            CMempoolAddressDelta delta(entry.GetTime(), prevout.nValue * -1, input.prevout.hash, input.prevout.n);
            mapAddress.insert(std::make_pair(key, delta));
            inserted.push_back(key);
        }  else if (prevout.scriptPubKey.IsPayToExchangeAddress()) {
            std::vector<unsigned char> hashBytes(prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23);
            CMempoolAddressDeltaKey key(AddressType::payToExchangeAddress, uint160(hashBytes), txhash, j, 1);
            CMempoolAddressDelta delta(entry.GetTime(), prevout.nValue * -1, input.prevout.hash, input.prevout.n);
            mapAddress.insert(std::make_pair(key, delta));
            inserted.push_back(key);
        }
    }

    for (unsigned int k = 0; k < tx.vout.size(); k++) {
        const CTxOut &out = tx.vout[k];
        if (out.scriptPubKey.IsPayToScriptHash()) {
            std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+2, out.scriptPubKey.begin()+22);
            CMempoolAddressDeltaKey key(AddressType::payToScriptHash, uint160(hashBytes), txhash, k, 0);
            mapAddress.insert(std::make_pair(key, CMempoolAddressDelta(entry.GetTime(), out.nValue)));
            inserted.push_back(key);
        } else if (out.scriptPubKey.IsPayToPublicKeyHash()) {
            std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);
            std::pair<addressDeltaMap::iterator,bool> ret;
            CMempoolAddressDeltaKey key(AddressType::payToPubKeyHash, uint160(hashBytes), txhash, k, 0);
            mapAddress.insert(std::make_pair(key, CMempoolAddressDelta(entry.GetTime(), out.nValue)));
            inserted.push_back(key);
        } else if (out.scriptPubKey.IsPayToExchangeAddress()) {
            std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);
            std::pair<addressDeltaMap::iterator,bool> ret;
            CMempoolAddressDeltaKey key(AddressType::payToExchangeAddress, uint160(hashBytes), txhash, k, 0);
            mapAddress.insert(std::make_pair(key, CMempoolAddressDelta(entry.GetTime(), out.nValue)));
            inserted.push_back(key);
        }
    }

    mapAddressInserted.insert(make_pair(txhash, inserted));
}

bool CTxMemPool::getAddressIndex(std::vector<std::pair<uint160, AddressType> > &addresses,
                                 std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > &results)
{
    LOCK(cs);
    for (std::vector<std::pair<uint160, AddressType> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        addressDeltaMap::iterator ait = mapAddress.lower_bound(CMempoolAddressDeltaKey((*it).second, (*it).first));
        while (ait != mapAddress.end() && (*ait).first.addressBytes == (*it).first && (*ait).first.type == (*it).second) {
            results.push_back(*ait);
            ait++;
        }
    }
    return true;
}

bool CTxMemPool::removeAddressIndex(const uint256 txhash)
{
    LOCK(cs);
    addressDeltaMapInserted::iterator it = mapAddressInserted.find(txhash);

    if (it != mapAddressInserted.end()) {
        std::vector<CMempoolAddressDeltaKey> keys = (*it).second;
        for (std::vector<CMempoolAddressDeltaKey>::iterator mit = keys.begin(); mit != keys.end(); mit++) {
            mapAddress.erase(*mit);
        }
        mapAddressInserted.erase(it);
    }

    return true;
}

void CTxMemPool::addSpentIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view)
{
    LOCK(cs);

    const CTransaction& tx = entry.GetTx();
    std::vector<CSpentIndexKey> inserted;

    uint256 txhash = tx.GetHash();
    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        const CTxIn input = tx.vin[j];
        if (tx.HasPrivateInputs()) {
            continue;
        }

        const CTxOut &prevout = view.AccessCoin(input.prevout).out;
        uint160 addressHash;
        AddressType addressType;

        if (prevout.scriptPubKey.IsPayToScriptHash()) {
            addressHash = uint160(std::vector<unsigned char> (prevout.scriptPubKey.begin()+2, prevout.scriptPubKey.begin()+22));
            addressType = AddressType::payToScriptHash;
        } else if (prevout.scriptPubKey.IsPayToPublicKeyHash()) {
            addressHash = uint160(std::vector<unsigned char> (prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23));
            addressType = AddressType::payToPubKeyHash;
        } else if (prevout.scriptPubKey.IsPayToExchangeAddress()) {
            addressHash = uint160(std::vector<unsigned char> (prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23));
            addressType = AddressType::payToExchangeAddress;
        } else {
            addressHash.SetNull();
            addressType = AddressType::unknown;
        }

        CSpentIndexKey key = CSpentIndexKey(input.prevout.hash, input.prevout.n);
        CSpentIndexValue value = CSpentIndexValue(txhash, j, -1, prevout.nValue, addressType, addressHash);

        mapSpent.insert(std::make_pair(key, value));
        inserted.push_back(key);

    }

    mapSpentInserted.insert(make_pair(txhash, inserted));
}

bool CTxMemPool::getSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value)
{
    LOCK(cs);
    mapSpentIndex::iterator it;

    it = mapSpent.find(key);
    if (it != mapSpent.end()) {
        value = it->second;
        return true;
    }
    return false;
}

bool CTxMemPool::removeSpentIndex(const uint256 txhash)
{
    LOCK(cs);
    mapSpentIndexInserted::iterator it = mapSpentInserted.find(txhash);

    if (it != mapSpentInserted.end()) {
        std::vector<CSpentIndexKey> keys = (*it).second;
        for (std::vector<CSpentIndexKey>::iterator mit = keys.begin(); mit != keys.end(); mit++) {
            mapSpent.erase(*mit);
        }
        mapSpentInserted.erase(it);
    }

    return true;
}

// Calculates descendants of entry that are not already in setDescendants, and adds to
// setDescendants. Assumes entryit is already a tx in the mempool and setMemPoolChildren
// is correct for tx and all descendants.
// Also assumes that if an entry is in setDescendants already, then all
// in-mempool descendants of it are already in setDescendants as well, so that we
// can save time by not iterating over those entries.
void CTxMemPool::CalculateDescendants(txiter entryit, setEntries &setDescendants)
{
    setEntries stage;
    if (setDescendants.count(entryit) == 0) {
        stage.insert(entryit);
    }
    // Traverse down the children of entry, only adding children that are not
    // accounted for in setDescendants already (because those children have either
    // already been walked, or will be walked in this iteration).
    while (!stage.empty()) {
        txiter it = *stage.begin();
        setDescendants.insert(it);
        stage.erase(it);

        const setEntries &setChildren = GetMemPoolChildren(it);
        BOOST_FOREACH(const txiter &childiter, setChildren) {
            if (!setDescendants.count(childiter)) {
                stage.insert(childiter);
            }
        }
    }
}

void CTxMemPool::removeRecursive(const CTransaction &origTx, MemPoolRemovalReason reason)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        setEntries txToRemove;
        txiter origit = mapTx.find(origTx.GetHash());
        if (origit != mapTx.end()) {
            txToRemove.insert(origit);
        } else {
            // When recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                auto it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txiter nextit = mapTx.find(it->second->GetHash());
                assert(nextit != mapTx.end());
                txToRemove.insert(nextit);
            }
        }
        setEntries setAllRemoves;
        BOOST_FOREACH(txiter it, txToRemove) {
            CalculateDescendants(it, setAllRemoves);
        }

        RemoveStaged(setAllRemoves, false, reason);
    }
}

void CTxMemPool::removeForReorg(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight, int flags)
{
    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    LOCK(cs);
    setEntries txToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        const CTransaction& tx = it->GetTx();
        LockPoints lp = it->GetLockPoints();
        bool validLP =  TestLockPointValidity(&lp);
        if (!CheckFinalTx(tx, flags) || !CheckSequenceLocks(*this, tx, flags, &lp, validLP)) {
            // Note if CheckSequenceLocks fails the LockPoints may still be invalid
            // So it's critical that we remove the tx and not depend on the LockPoints.
            txToRemove.insert(it);
        } else if (it->GetSpendsCoinbase()) {
            BOOST_FOREACH(const CTxIn& txin, tx.vin) {
                indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
                if (it2 != mapTx.end())
                    continue;
                const Coin &coin = pcoins->AccessCoin(txin.prevout);
                if (nCheckFrequency != 0) assert(!coin.IsSpent());
                if (coin.IsSpent() || (coin.IsCoinBase() && ((signed long)nMemPoolHeight) - coin.nHeight < COINBASE_MATURITY)) {
                    txToRemove.insert(it);
                    break;
                }
            }
        }
        if (!validLP) {
            mapTx.modify(it, update_lock_points(lp));
        }
    }
    setEntries setAllRemoves;
    for (txiter it : txToRemove) {
        CalculateDescendants(it, setAllRemoves);
    }
    RemoveStaged(setAllRemoves, false, MemPoolRemovalReason::REORG);
}

void CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    BOOST_FOREACH(const CTxIn &txin, tx.vin) {
        auto it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second;
            if (txConflict != tx)
            {
                ClearPrioritisation(txConflict.GetHash());
                removeRecursive(txConflict, MemPoolRemovalReason::CONFLICT);
            }
        }
    }
}

void CTxMemPool::removeProTxPubKeyConflicts(const CTransaction &tx, const CKeyID &keyId)
{
    if (mapProTxPubKeyIDs.count(keyId)) {
        uint256 conflictHash = mapProTxPubKeyIDs[keyId];
        if (conflictHash != tx.GetHash() && mapTx.count(conflictHash)) {
            removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }
}

void CTxMemPool::removeProTxPubKeyConflicts(const CTransaction &tx, const CBLSPublicKey &pubKey)
{
    if (mapProTxBlsPubKeyHashes.count(pubKey.GetHash())) {
        uint256 conflictHash = mapProTxBlsPubKeyHashes[pubKey.GetHash()];
        if (conflictHash != tx.GetHash() && mapTx.count(conflictHash)) {
            removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }
}

void CTxMemPool::removeProTxCollateralConflicts(const CTransaction &tx, const COutPoint &collateralOutpoint)
{
    if (mapProTxCollaterals.count(collateralOutpoint)) {
        uint256 conflictHash = mapProTxCollaterals[collateralOutpoint];
        if (conflictHash != tx.GetHash() && mapTx.count(conflictHash)) {
            removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }
}

void CTxMemPool::removeProTxSpentCollateralConflicts(const CTransaction &tx)
{
    // Remove TXs that refer to a MN for which the collateral was spent
    auto removeSpentCollateralConflict = [&](const uint256& proTxHash) {
        // Can't use equal_range here as every call to removeRecursive might invalidate iterators
        while (true) {
            auto it = mapProTxRefs.find(proTxHash);
            if (it == mapProTxRefs.end()) {
                break;
            }
            auto conflictIt = mapTx.find(it->second);
            if (conflictIt != mapTx.end()) {
                removeRecursive(conflictIt->GetTx(), MemPoolRemovalReason::CONFLICT);
            } else {
                auto protxIt = mapTx.find(proTxHash);
                if (protxIt != mapTx.end()) {
                    // Remove proTx from the mempool because its collateral has been spent
                    removeRecursive(protxIt->GetTx(), MemPoolRemovalReason::CONFLICT);
                }
                else {
                    // Should not happen as we track referencing TXs in addUnchecked/removeUnchecked.
                    // But lets be on the safe side and not run into an endless loop...
                    LogPrintf("%s: ERROR: found invalid TX ref in mapProTxRefs, proTxHash=%s, txHash=%s\n", __func__, proTxHash.ToString(), it->second.ToString());
                    mapProTxRefs.erase(it);
                }
            }
        }
    };
    auto mnList = deterministicMNManager->GetListAtChainTip();
    for (const auto& in : tx.vin) {
        auto collateralIt = mapProTxCollaterals.find(in.prevout);
        if (collateralIt != mapProTxCollaterals.end()) {
            // These are not yet mined ProRegTxs
            removeSpentCollateralConflict(collateralIt->second);
        }
        auto dmn = mnList.GetMNByCollateral(in.prevout);
        if (dmn) {
            // These are updates refering to a mined ProRegTx
            removeSpentCollateralConflict(dmn->proTxHash);
        }
    }
}

void CTxMemPool::removeProTxKeyChangedConflicts(const CTransaction &tx, const uint256& proTxHash, const uint256& newKeyHash)
{
    std::set<uint256> conflictingTxs;
    for (auto its = mapProTxRefs.equal_range(proTxHash); its.first != its.second; ++its.first) {
        auto txit = mapTx.find(its.first->second);
        if (txit == mapTx.end()) {
            continue;
        }
        if (txit->validForProTxKey != newKeyHash) {
            conflictingTxs.emplace(txit->GetTx().GetHash());
        }
    }
    for (const auto& txHash : conflictingTxs) {
        auto& tx = mapTx.find(txHash)->GetTx();
        removeRecursive(tx, MemPoolRemovalReason::CONFLICT);
    }
}

void CTxMemPool::removeProTxConflicts(const CTransaction &tx)
{
    removeProTxSpentCollateralConflicts(tx);

    if (tx.nType == TRANSACTION_PROVIDER_REGISTER) {
        CProRegTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrintf("%s: ERROR: Invalid transaction payload, tx: %s", __func__, tx.ToString());
            return;
        }

        if (mapProTxAddresses.count(proTx.addr)) {
            uint256 conflictHash = mapProTxAddresses[proTx.addr];
            if (conflictHash != tx.GetHash() && mapTx.count(conflictHash)) {
                removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
            }
        }
        removeProTxPubKeyConflicts(tx, proTx.keyIDOwner);
        removeProTxPubKeyConflicts(tx, proTx.pubKeyOperator);
        if (!proTx.collateralOutpoint.hash.IsNull()) {
            removeProTxCollateralConflicts(tx, proTx.collateralOutpoint);
        }
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_SERVICE) {
        CProUpServTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrintf("%s: ERROR: Invalid transaction payload, tx: %s", __func__, tx.ToString());
            return;
        }

        if (mapProTxAddresses.count(proTx.addr)) {
            uint256 conflictHash = mapProTxAddresses[proTx.addr];
            if (conflictHash != tx.GetHash() && mapTx.count(conflictHash)) {
                removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
            }
        }
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REGISTRAR) {
        CProUpRegTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrintf("%s: ERROR: Invalid transaction payload, tx: %s", __func__, tx.ToString());
            return;
        }

        removeProTxPubKeyConflicts(tx, proTx.pubKeyOperator);
        removeProTxKeyChangedConflicts(tx, proTx.proTxHash, ::SerializeHash(proTx.pubKeyOperator));
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REVOKE) {
        CProUpRevTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrintf("%s: ERROR: Invalid transaction payload, tx: %s", __func__, tx.ToString());
            return;
        }

        removeProTxKeyChangedConflicts(tx, proTx.proTxHash, ::SerializeHash(CBLSPublicKey()));
    }
}

/**
 * Called when a block is connected. Removes from mempool and updates the miner fee estimator.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight)
{
    LOCK(cs);
    std::vector<const CTxMemPoolEntry*> entries;
    for (const auto& tx : vtx)
    {
        uint256 hash = tx->GetHash();

        indexed_transaction_set::iterator i = mapTx.find(hash);
        if (i != mapTx.end())
            entries.push_back(&*i);
    }
    // Before the txs in the new block have been removed from the mempool, update policy estimates
    minerPolicyEstimator->processBlock(nBlockHeight, entries);
    for (const auto& tx : vtx)
    {
        txiter it = mapTx.find(tx->GetHash());
        if (it != mapTx.end()) {
            setEntries stage;
            stage.insert(it);
            RemoveStaged(stage, true, MemPoolRemovalReason::BLOCK);
        }
        removeConflicts(*tx);
        removeProTxConflicts(*tx);
        ClearPrioritisation(tx->GetHash());
    }
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = true;
}

void CTxMemPool::_clear()
{
    mapLinks.clear();
    mapTx.clear();
    mapNextTx.clear();
    mapProTxAddresses.clear();
    mapProTxPubKeyIDs.clear();
    totalTxSize = 0;
    cachedInnerUsage = 0;
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = false;
    rollingMinimumFeeRate = 0;
    lelantusState.Reset();
    sparkState.Reset();
    ++nTransactionsUpdated;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    _clear();
}

void CTxMemPool::check(const CCoinsViewCache *pcoins) const
{
    if (nCheckFrequency == 0)
        return;

    if (GetRand(std::numeric_limits<uint32_t>::max()) >= nCheckFrequency)
        return;

    LogPrint("mempool", "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    uint64_t innerUsage = 0;

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(pcoins));
    const int64_t nSpendHeight = GetSpendHeight(mempoolDuplicate);

    LOCK(cs);
    std::list<const CTxMemPoolEntry*> waitingOnDependants;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        FIRO_UNUSED unsigned int i = 0;
        checkTotal += it->GetTxSize();
        innerUsage += it->DynamicMemoryUsage();
        const CTransaction& tx = it->GetTx();
        txlinksMap::const_iterator linksiter = mapLinks.find(it);
        assert(linksiter != mapLinks.end());
        const TxLinks &links = linksiter->second;
        innerUsage += memusage::DynamicUsage(links.children);
        if (!tx.HasPrivateInputs())
            innerUsage += memusage::DynamicUsage(links.parents);
        bool fDependsWait = false;
        setEntries setParentCheck;
        FIRO_UNUSED int64_t parentSizes = 0;
        FIRO_UNUSED int64_t parentSigOpCost = 0;
        if (!tx.HasPrivateInputs()) {
            BOOST_FOREACH(const CTxIn &txin, tx.vin) {
                // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
                indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
                if (it2 != mapTx.end()) {
                    const CTransaction& tx2 = it2->GetTx();
                    assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                    fDependsWait = true;
                    if (setParentCheck.insert(it2).second) {
                        parentSizes += it2->GetTxSize();
                        parentSigOpCost += it2->GetSigOpCost();
                    }
                } else {
                    assert(pcoins->HaveCoin(txin.prevout));
                }
                // Check whether its inputs are marked in mapNextTx.
                auto it3 = mapNextTx.find(txin.prevout);
                assert(it3 != mapNextTx.end());
                assert(it3->first == &txin.prevout);
                assert(it3->second == &tx);
                i++;
            }
        }
        assert(setParentCheck == GetMemPoolParents(it));
        // Verify ancestor state is correct.
        setEntries setAncestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        CalculateMemPoolAncestors(*it, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy);
        uint64_t nCountCheck = setAncestors.size() + 1;
        uint64_t nSizeCheck = it->GetTxSize();
        CAmount nFeesCheck = it->GetModifiedFee();
        int64_t nSigOpCheck = it->GetSigOpCost();

        BOOST_FOREACH(txiter ancestorIt, setAncestors) {
            nSizeCheck += ancestorIt->GetTxSize();
            nFeesCheck += ancestorIt->GetModifiedFee();
            nSigOpCheck += ancestorIt->GetSigOpCost();
        }

        assert(it->GetCountWithAncestors() == nCountCheck);
        assert(it->GetSizeWithAncestors() == nSizeCheck);
        assert(it->GetSigOpCostWithAncestors() == nSigOpCheck);
        assert(it->GetModFeesWithAncestors() == nFeesCheck);

        // Check children against mapNextTx
        CTxMemPool::setEntries setChildrenCheck;
        auto iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetHash(), 0));
        int64_t childSizes = 0;
        for (; iter != mapNextTx.end() && iter->first->hash == it->GetTx().GetHash(); ++iter) {
            txiter childit = mapTx.find(iter->second->GetHash());
            assert(childit != mapTx.end()); // mapNextTx points to in-mempool transactions
            if (setChildrenCheck.insert(childit).second) {
                childSizes += childit->GetTxSize();
            }
        }
        assert(setChildrenCheck == GetMemPoolChildren(it));
        // Also check to make sure size is greater than sum with immediate children.
        // just a sanity check, not definitive that this calc is correct...
        assert(it->GetSizeWithDescendants() >= childSizes + it->GetTxSize());

        if (fDependsWait)
            waitingOnDependants.push_back(&(*it));
        else {
            CValidationState state;
            bool fCheckResult = tx.IsCoinBase() || tx.HasPrivateInputs() ||
                    Consensus::CheckTxInputs(tx, state, mempoolDuplicate, nSpendHeight);

            assert(fCheckResult);
            UpdateCoins(tx, mempoolDuplicate, 1000000);
        }
    }
    unsigned int stepsSinceLastRemove = 0;
    while (!waitingOnDependants.empty()) {
        const CTxMemPoolEntry* entry = waitingOnDependants.front();
        waitingOnDependants.pop_front();
        CValidationState state;
        if (!mempoolDuplicate.HaveInputs(entry->GetTx())) {
            waitingOnDependants.push_back(entry);
            stepsSinceLastRemove++;
            assert(stepsSinceLastRemove < waitingOnDependants.size());
        } else {
            const CTransaction &tx = entry->GetTx();
            bool fCheckResult = tx.IsCoinBase() || tx.HasPrivateInputs() ||
                Consensus::CheckTxInputs(entry->GetTx(), state, mempoolDuplicate, nSpendHeight);
            assert(fCheckResult);
            UpdateCoins(entry->GetTx(), mempoolDuplicate, 1000000);
            stepsSinceLastRemove = 0;
        }
    }
    for (auto it = mapNextTx.cbegin(); it != mapNextTx.cend(); it++) {
        uint256 hash = it->second->GetHash();
        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
        const CTransaction& tx = it2->GetTx();
        assert(it2 != mapTx.end());
        assert(&tx == it->second);
    }

    assert(totalTxSize == checkTotal);
    assert(innerUsage == cachedInnerUsage);
}

bool CTxMemPool::CompareDepthAndScore(const uint256& hasha, const uint256& hashb)
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hasha);
    if (i == mapTx.end()) return false;
    indexed_transaction_set::const_iterator j = mapTx.find(hashb);
    if (j == mapTx.end()) return true;
    uint64_t counta = i->GetCountWithAncestors();
    uint64_t countb = j->GetCountWithAncestors();
    if (counta == countb) {
        return CompareTxMemPoolEntryByScore()(*i, *j);
    }
    return counta < countb;
}

namespace {
class DepthAndScoreComparator
{
public:
    bool operator()(const CTxMemPool::indexed_transaction_set::const_iterator& a, const CTxMemPool::indexed_transaction_set::const_iterator& b)
    {
        uint64_t counta = a->GetCountWithAncestors();
        uint64_t countb = b->GetCountWithAncestors();
        if (counta == countb) {
            return CompareTxMemPoolEntryByScore()(*a, *b);
        }
        return counta < countb;
    }
};
}

std::vector<CTxMemPool::indexed_transaction_set::const_iterator> CTxMemPool::GetSortedDepthAndScore() const
{
    std::vector<indexed_transaction_set::const_iterator> iters;
    AssertLockHeld(cs);

    iters.reserve(mapTx.size());

    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi) {
        iters.push_back(mi);
    }
    std::sort(iters.begin(), iters.end(), DepthAndScoreComparator());
    return iters;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    LOCK(cs);
    auto iters = GetSortedDepthAndScore();

    vtxid.clear();
    vtxid.reserve(mapTx.size());

    for (auto it : iters) {
        vtxid.push_back(it->GetTx().GetHash());
    }
}

static TxMempoolInfo GetInfo(CTxMemPool::indexed_transaction_set::const_iterator it) {
    return TxMempoolInfo{it->GetSharedTx(), it->GetTime(), CFeeRate(it->GetFee(), it->GetTxSize()), it->GetModifiedFee() - it->GetFee()};
}

std::vector<TxMempoolInfo> CTxMemPool::infoAll() const
{
    LOCK(cs);
    auto iters = GetSortedDepthAndScore();

    std::vector<TxMempoolInfo> ret;
    ret.reserve(mapTx.size());
    for (auto it : iters) {
        ret.push_back(GetInfo(it));
    }

    return ret;
}

CTransactionRef CTxMemPool::get(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetSharedTx();
}

TxMempoolInfo CTxMemPool::info(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return TxMempoolInfo();
    return GetInfo(i);
}

bool CTxMemPool::existsProviderTxConflict(const CTransaction &tx) const {
    LOCK(cs);

    auto hasKeyChangeInMempool = [&](const uint256& proTxHash) {
        for (auto its = mapProTxRefs.equal_range(proTxHash); its.first != its.second; ++its.first) {
            auto txit = mapTx.find(its.first->second);
            if (txit == mapTx.end()) {
                continue;
            }
            if (txit->isKeyChangeProTx) {
                return true;
            }
        }
        return false;
    };

    if (tx.nType == TRANSACTION_PROVIDER_REGISTER) {
        CProRegTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrintf("%s: ERROR: Invalid transaction payload, tx: %s", __func__, tx.ToString());
            return true; // i.e. can't decode payload == conflict
        }
        if (mapProTxAddresses.count(proTx.addr) || mapProTxPubKeyIDs.count(proTx.keyIDOwner) || mapProTxBlsPubKeyHashes.count(proTx.pubKeyOperator.GetHash()))
            return true;
        if (!proTx.collateralOutpoint.hash.IsNull()) {
            if (mapProTxCollaterals.count(proTx.collateralOutpoint)) {
                // there is another ProRegTx that refers to the same collateral
                return true;
            }
            if (mapNextTx.count(proTx.collateralOutpoint)) {
                // there is another tx that spends the collateral
                return true;
            }
        }
        return false;
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_SERVICE) {
        CProUpServTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrintf("%s: ERROR: Invalid transaction payload, tx: %s", __func__, tx.ToString());
            return true; // i.e. can't decode payload == conflict
        }
        auto it = mapProTxAddresses.find(proTx.addr);
        return it != mapProTxAddresses.end() && it->second != proTx.proTxHash;
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REGISTRAR) {
        CProUpRegTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrintf("%s: ERROR: Invalid transaction payload, tx: %s", __func__, tx.ToString());
            return true; // i.e. can't decode payload == conflict
        }

        // this method should only be called with validated ProTxs
        auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(proTx.proTxHash);
        if (!dmn) {
            LogPrintf("%s: ERROR: Masternode is not in the list, proTxHash: %s", __func__, proTx.proTxHash.ToString());
            return true; // i.e. failed to find validated ProTx == conflict
        }
        // only allow one operator key change in the mempool
        if (dmn->pdmnState->pubKeyOperator.Get() != proTx.pubKeyOperator) {
            if (hasKeyChangeInMempool(proTx.proTxHash)) {
                return true;
            }
        }

        auto it = mapProTxBlsPubKeyHashes.find(proTx.pubKeyOperator.GetHash());
        return it != mapProTxBlsPubKeyHashes.end() && it->second != proTx.proTxHash;
    } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REVOKE) {
        CProUpRevTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrintf("%s: ERROR: Invalid transaction payload, tx: %s", __func__, tx.ToString());
            return true; // i.e. can't decode payload == conflict
        }

        // this method should only be called with validated ProTxs
        auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(proTx.proTxHash);
        if (!dmn) {
            LogPrintf("%s: ERROR: Masternode is not in the list, proTxHash: %s", __func__, proTx.proTxHash.ToString());
            return true; // i.e. failed to find validated ProTx == conflict
        }
        // only allow one operator key change in the mempool
        if (dmn->pdmnState->pubKeyOperator.Get() != CBLSPublicKey()) {
            if (hasKeyChangeInMempool(proTx.proTxHash)) {
                return true;
            }
        }
    }
    return false;
}

CFeeRate CTxMemPool::estimateFee(int nBlocks) const
{
    LOCK(cs);
    return minerPolicyEstimator->estimateFee(nBlocks);
}
CFeeRate CTxMemPool::estimateSmartFee(int nBlocks, int *answerFoundAtBlocks) const
{
    LOCK(cs);
    return minerPolicyEstimator->estimateSmartFee(nBlocks, answerFoundAtBlocks, *this);
}
double CTxMemPool::estimatePriority(int nBlocks) const
{
    LOCK(cs);
    return minerPolicyEstimator->estimatePriority(nBlocks);
}
double CTxMemPool::estimateSmartPriority(int nBlocks, int *answerFoundAtBlocks) const
{
    LOCK(cs);
    return minerPolicyEstimator->estimateSmartPriority(nBlocks, answerFoundAtBlocks, *this);
}

bool
CTxMemPool::WriteFeeEstimates(CAutoFile& fileout) const
{
    try {
        LOCK(cs);
        fileout << 139900; // version required to read: 0.13.99 or later
        fileout << CLIENT_VERSION; // version that wrote the file
        minerPolicyEstimator->Write(fileout);
    }
    catch (const std::exception&) {
        LogPrintf("CTxMemPool::WriteFeeEstimates(): unable to write policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

bool
CTxMemPool::ReadFeeEstimates(CAutoFile& filein)
{
    try {
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION)
            return error("CTxMemPool::ReadFeeEstimates(): up-version (%d) fee estimate file", nVersionRequired);
        LOCK(cs);
        minerPolicyEstimator->Read(filein, nVersionThatWrote);
    }
    catch (const std::exception&) {
        LogPrintf("CTxMemPool::ReadFeeEstimates(): unable to read policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

void CTxMemPool::PrioritiseTransaction(const uint256 hash, const std::string strHash, double dPriorityDelta, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        std::pair<double, CAmount> &deltas = mapDeltas[hash];
        deltas.first += dPriorityDelta;
        deltas.second += nFeeDelta;
        txiter it = mapTx.find(hash);
        if (it != mapTx.end()) {
            mapTx.modify(it, update_fee_delta(deltas.second));
            // Now update all ancestors' modified fees with descendants
            setEntries setAncestors;
            uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
            std::string dummy;
            CalculateMemPoolAncestors(*it, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
            BOOST_FOREACH(txiter ancestorIt, setAncestors) {
                mapTx.modify(ancestorIt, update_descendant_state(0, nFeeDelta, 0));
            }
            // Now update all descendants' modified fees with ancestors
            setEntries setDescendants;
            CalculateDescendants(it, setDescendants);
            setDescendants.erase(it);
            BOOST_FOREACH(txiter descendantIt, setDescendants) {
                mapTx.modify(descendantIt, update_ancestor_state(0, nFeeDelta, 0, 0));
            }
            ++nTransactionsUpdated;
        }
    }
    LogPrintf("PrioritiseTransaction: %s priority += %f, fee += %d\n", strHash, dPriorityDelta, FormatMoney(nFeeDelta));
}

void CTxMemPool::ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta) const
{
    LOCK(cs);
    std::map<uint256, std::pair<double, CAmount> >::const_iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const std::pair<double, CAmount> &deltas = pos->second;
    dPriorityDelta += deltas.first;
    nFeeDelta += deltas.second;
}

void CTxMemPool::ClearPrioritisation(const uint256 hash)
{
    LOCK(cs);
    mapDeltas.erase(hash);
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(tx.vin[i].prevout.hash))
            return false;
    return true;
}

bool CTxMemPool::IsTransactionAllowed(const CTransaction &tx, CValidationState &state) const
{
    return sporkManager.IsTransactionAllowed(tx, state);
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransactionRef ptx = mempool.get(outpoint.hash);
    if (ptx) {
        if (outpoint.n < ptx->vout.size()) {
            coin = Coin(ptx->vout[outpoint.n], MEMPOOL_HEIGHT, false);
            return true;
        } else {
            return false;
        }
    }
    return (base->GetCoin(outpoint, coin) && !coin.IsSpent());
}

bool CCoinsViewMemPool::HaveCoin(const COutPoint &outpoint) const {
    return mempool.exists(outpoint) || base->HaveCoin(outpoint);
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 15 pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 15 * sizeof(void*)) * mapTx.size() + memusage::DynamicUsage(mapNextTx) + memusage::DynamicUsage(mapDeltas) + memusage::DynamicUsage(mapLinks) + memusage::DynamicUsage(vTxHashes) + cachedInnerUsage;
}

double CTxMemPool::UsedMemoryShare() const
{
    // use 1000000 instead of real bytes number in megabyte because of
    // this param is calculated in such way in other places (see AppInit
    // function in src/init.cpp or mempoolInfoToJSON function in
    // src/rpc/blockchain.cpp)
    size_t maxmempool = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    return double(DynamicMemoryUsage()) / maxmempool;
}

void CTxMemPool::RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason) {
    AssertLockHeld(cs);
    UpdateForRemoveFromMempool(stage, updateDescendants);
    BOOST_FOREACH(const txiter& it, stage) {
        removeUnchecked(it, reason);
    }
}

int CTxMemPool::Expire(int64_t time) {
    LOCK(cs);
    indexed_transaction_set::index<entry_time>::type::iterator it = mapTx.get<entry_time>().begin();
    setEntries toremove;
    while (it != mapTx.get<entry_time>().end() && it->GetTime() < time) {
        // locked txes do not expire until mined and have sufficient confirmations
        if (llmq::quorumInstantSendManager->IsLocked(it->GetTx().GetHash())) {
            it++;
            continue;
        }
        toremove.insert(mapTx.project<0>(it));
        it++;
    }
    setEntries stage;
    BOOST_FOREACH(txiter removeit, toremove) {
        CalculateDescendants(removeit, stage);
    }
    RemoveStaged(stage, false, MemPoolRemovalReason::EXPIRY);
    return stage.size();
}

bool CTxMemPool::addUnchecked(const uint256&hash, const CTxMemPoolEntry &entry, bool validFeeEstimate)
{
    LOCK(cs);
    setEntries setAncestors;
    uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    CalculateMemPoolAncestors(entry, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy);
    return addUnchecked(hash, entry, setAncestors, validFeeEstimate);
}

void CTxMemPool::UpdateChild(txiter entry, txiter child, bool add)
{
    setEntries s;
    if (add && mapLinks[entry].children.insert(child).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && mapLinks[entry].children.erase(child)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

void CTxMemPool::UpdateParent(txiter entry, txiter parent, bool add)
{
    setEntries s;
    if (add && mapLinks[entry].parents.insert(parent).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && mapLinks[entry].parents.erase(parent)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

const CTxMemPool::setEntries & CTxMemPool::GetMemPoolParents(txiter entry) const
{
    assert (entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.parents;
}

const CTxMemPool::setEntries & CTxMemPool::GetMemPoolChildren(txiter entry) const
{
    assert (entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.children;
}

CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {
    LOCK(cs);
    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
        return CFeeRate(rollingMinimumFeeRate);

    int64_t time = GetTime();
    if (time > lastRollingFeeUpdate + 10) {
        double halflife = ROLLING_FEE_HALFLIFE;
        if (DynamicMemoryUsage() < sizelimit / 4)
            halflife /= 4;
        else if (DynamicMemoryUsage() < sizelimit / 2)
            halflife /= 2;

        rollingMinimumFeeRate = rollingMinimumFeeRate / pow(2.0, (time - lastRollingFeeUpdate) / halflife);
        lastRollingFeeUpdate = time;

        if (rollingMinimumFeeRate < (double)incrementalRelayFee.GetFeePerK() / 2) {
            rollingMinimumFeeRate = 0;
            return CFeeRate(0);
        }
    }
    return std::max(CFeeRate(rollingMinimumFeeRate), incrementalRelayFee);
}

void CTxMemPool::trackPackageRemoved(const CFeeRate& rate) {
    AssertLockHeld(cs);
    if (rate.GetFeePerK() > rollingMinimumFeeRate) {
        rollingMinimumFeeRate = rate.GetFeePerK();
        blockSinceLastRollingFeeBump = false;
    }
}

void CTxMemPool::TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining) {
    LOCK(cs);

    unsigned nTxnRemoved = 0;
    CFeeRate maxFeeRateRemoved(0);
    while (!mapTx.empty() && DynamicMemoryUsage() > sizelimit) {
        indexed_transaction_set::index<descendant_score>::type::iterator it = mapTx.get<descendant_score>().begin();

        // We set the new mempool min fee to the feerate of the removed set, plus the
        // "minimum reasonable fee rate" (ie some value under which we consider txn
        // to have 0 fee). This way, we don't allow txn to enter mempool with feerate
        // equal to txn which were removed with no block in between.
        CFeeRate removed(it->GetModFeesWithDescendants(), it->GetSizeWithDescendants());
        removed += incrementalRelayFee;
        trackPackageRemoved(removed);
        maxFeeRateRemoved = std::max(maxFeeRateRemoved, removed);

        setEntries stage;
        CalculateDescendants(mapTx.project<0>(it), stage);
        nTxnRemoved += stage.size();

        std::vector<CTransaction> txn;
        if (pvNoSpendsRemaining) {
            txn.reserve(stage.size());
            BOOST_FOREACH(txiter iter, stage)
                txn.push_back(iter->GetTx());
        }
        RemoveStaged(stage, false, MemPoolRemovalReason::SIZELIMIT);
        if (pvNoSpendsRemaining) {
            BOOST_FOREACH(const CTransaction& tx, txn) {
                BOOST_FOREACH(const CTxIn& txin, tx.vin) {
                    if (exists(txin.prevout.hash)) continue;
                    if (!mapNextTx.count(txin.prevout)) {
                        pvNoSpendsRemaining->push_back(txin.prevout);
                    }
                }
            }
        }
    }

    if (maxFeeRateRemoved > CFeeRate(0))
        LogPrint("mempool", "Removed %u txn, rolling minimum fee bumped to %s\n", nTxnRemoved, maxFeeRateRemoved.ToString());
}

bool CTxMemPool::TransactionWithinChainLimit(const uint256& txid, size_t chainLimit) const {
    LOCK(cs);
    auto it = mapTx.find(txid);
    return it == mapTx.end() || (it->GetCountWithAncestors() < chainLimit &&
       it->GetCountWithDescendants() < chainLimit);
}

/******************************************************************************/

CTxPoolAggregate::CTxPoolAggregate(const CFeeRate& minReasonableRelayFee)
: stemTxPool(minReasonableRelayFee)
{}

CTxMemPool & CTxPoolAggregate::getStemTxPool() {
    return stemTxPool;
}

void CTxPoolAggregate::UpdateTransactionsFromBlock(const std::vector <uint256> &vHashesToUpdate) {
    mempool.UpdateTransactionsFromBlock(vHashesToUpdate);
    stemTxPool.UpdateTransactionsFromBlock(vHashesToUpdate);
}

void CTxPoolAggregate::AddTransactionsUpdated(unsigned int n) {
    mempool.AddTransactionsUpdated(n);
    stemTxPool.AddTransactionsUpdated(n);
}

void CTxPoolAggregate::removeForReorg(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight, int flags) {
    mempool.removeForReorg(pcoins, nMemPoolHeight, flags);
    stemTxPool.removeForReorg(pcoins, nMemPoolHeight, flags);
}

void CTxPoolAggregate::PrioritiseTransaction(const uint256 hash, const std::string strHash, double dPriorityDelta,
                                       const CAmount &nFeeDelta) {
    mempool.PrioritiseTransaction(hash, strHash, dPriorityDelta, nFeeDelta);
    stemTxPool.PrioritiseTransaction(hash, strHash, dPriorityDelta, nFeeDelta);
}

void CTxPoolAggregate::setSanityCheck(double dFrequency) {
    mempool.setSanityCheck(dFrequency);
    stemTxPool.setSanityCheck(dFrequency);
}

void CTxPoolAggregate::getTransactions(std::set<uint256>& setTxid) {
    mempool.getTransactions(setTxid);
    stemTxPool.getTransactions(setTxid);
}

void CTxPoolAggregate::check(const CCoinsViewCache *pcoins) const {
    mempool.check(pcoins);
    stemTxPool.check(pcoins);
}

CTransactionRef CTxPoolAggregate::get(const uint256& hash) const {
    CTransactionRef ptx = mempool.get(hash);
    if(ptx) {
        return ptx;
    }
    return stemTxPool.get(hash);
}

void CTxPoolAggregate::clear() {
    mempool.clear();
    stemTxPool.clear();
}

void CTxPoolAggregate::removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight) {
    mempool.removeForBlock(vtx, nBlockHeight);
    stemTxPool.removeForBlock(vtx, nBlockHeight);
}

void CTxPoolAggregate::removeRecursive(const CTransaction &tx, MemPoolRemovalReason reason) {
    mempool.removeRecursive(tx, reason);
    stemTxPool.removeRecursive(tx, reason);
}

SaltedTxidHasher::SaltedTxidHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max())) {}
