// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "evo/spork.h"
#include "llmq/quorums_chainlocks.h"
#include "llmq/quorums_instantsend.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "validation.h"
#include "validationinterface.h"

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>

namespace llmq
{
struct CInstantSendManagerTestAccess
{
    static void Enable(CInstantSendManager& manager)
    {
        manager.isNewInstantSendEnabled = true;
    }

    static uint256 AddPending(CInstantSendManager& manager, const CInstantSendLock& islock)
    {
        LOCK(manager.cs);
        const uint256 hash = ::SerializeHash(islock);
        manager.pendingNoTxInstantSendLocks.emplace(hash,
            CInstantSendManager::PendingInstantSendLock{-1, islock, nullptr, nullptr, {}});
        manager.pendingInstantSendLocksByTxid.emplace(islock.txid, hash);
        return hash;
    }

    static bool HasCallbackTransaction(CInstantSendManager& manager, const uint256& hash,
                                       const CTransactionRef& tx, const CBlockIndex* pindex)
    {
        LOCK(manager.cs);
        const auto& pending = manager.pendingNoTxInstantSendLocks.at(hash);
        return pending.tx && pending.tx->GetHash() == tx->GetHash() && pending.pindexMined == pindex;
    }

    static bool ProcessPending(CInstantSendManager& manager)
    {
        return manager.ProcessPendingInstantSendLocks();
    }

    static void ProcessLock(CInstantSendManager& manager, const CInstantSendLock& islock)
    {
        manager.ProcessInstantSendLock(-1, ::SerializeHash(islock), islock);
    }

    static void WriteLock(CInstantSendManager& manager, const CInstantSendLock& islock)
    {
        LOCK(manager.cs);
        manager.db.WriteNewInstantSendLock(::SerializeHash(islock), islock);
    }

    static bool RemoveConfirmed(CInstantSendManager& manager, int height, const uint256& hash)
    {
        LOCK(manager.cs);
        return manager.db.RemoveConfirmedInstantSendLocks(height).count(hash) != 0;
    }

    static void AddUnverified(CInstantSendManager& manager, const CInstantSendLock& islock)
    {
        LOCK(manager.cs);
        manager.pendingInstantSendLocks.emplace(::SerializeHash(islock), std::make_pair(-1, islock));
    }

    static void SetChainLock(CChainLocksHandler& handler, const CBlockIndex* pindex)
    {
        LOCK(handler.cs);
        handler.isEnforced = pindex != nullptr;
        handler.bestChainLockBlockIndex = pindex;
    }

    static void TrackConflict(CInstantSendManager& manager, const CTransactionRef& tx)
    {
        LOCK(manager.cs);
        manager.AddNonLockedTx(tx);
        for (const auto& in : tx->vin) {
            manager.inputRequestIds.emplace(::SerializeHash(std::make_pair(std::string("inlock"), in.prevout)));
        }
    }

    static bool TrackingEmpty(CInstantSendManager& manager)
    {
        LOCK(manager.cs);
        return manager.nonLockedTxs.empty() && manager.nonLockedTxsByInputs.empty() && manager.inputRequestIds.empty();
    }
};
} // namespace llmq

namespace
{
CTransactionRef MakeTransaction(const uint256& parent, uint32_t output = 0)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(parent, output));
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    return MakeTransactionRef(tx);
}

llmq::CInstantSendLock MakeLock(const CTransactionRef& tx)
{
    llmq::CInstantSendLock islock;
    islock.txid = tx->GetHash();
    for (const auto& in : tx->vin) {
        islock.inputs.emplace_back(in.prevout);
    }
    return islock;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(llmq_instantsend_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(active_state_tracks_sporks_without_clearing_pending_locks)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    const auto islock = MakeLock(MakeTransaction(uint256S("1")));
    llmq::CInstantSendManagerTestAccess::AddPending(manager, islock);
    CBlockIndex enabled;
    CBlockIndex disabled;
    disabled.SetActiveDisablingSporks({{CSporkAction::featureInstantSend, {0, 0}}});

    LOCK(cs_main);
    manager.UpdateActiveState(nullptr);
    BOOST_CHECK(!manager.IsNewInstantSendEnabled());
    manager.UpdateActiveState(&enabled);
    BOOST_CHECK(manager.IsNewInstantSendEnabled());
    BOOST_CHECK(manager.IsWaitingForTx(islock.txid));
    manager.UpdateActiveState(&disabled);
    BOOST_CHECK(!manager.IsNewInstantSendEnabled());
    manager.UpdateActiveState(&enabled);
    BOOST_CHECK(manager.IsNewInstantSendEnabled());
    BOOST_CHECK(manager.IsWaitingForTx(islock.txid));
    manager.UpdateActiveState(&disabled);
    BOOST_CHECK(!manager.IsNewInstantSendEnabled());
    manager.UpdateActiveState(&enabled);
    BOOST_CHECK(manager.IsNewInstantSendEnabled());
    manager.UpdateActiveState(nullptr);
    BOOST_CHECK(!manager.IsNewInstantSendEnabled());
    manager.UpdateActiveState(&enabled);
    BOOST_CHECK(manager.IsWaitingForTx(islock.txid));
}

BOOST_AUTO_TEST_CASE(block_callback_completes_pending_lock_without_txindex)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    llmq::CInstantSendManagerTestAccess::Enable(manager);
    const auto tx = MakeTransaction(uint256S("1"));
    const auto islock = MakeLock(tx);
    const uint256 hash = llmq::CInstantSendManagerTestAccess::AddPending(manager, islock);
    const auto* pindex = chainActive.Tip();
    const auto updates = mempool.GetTransactionsUpdated();

    const bool previousTxIndex = fTxIndex;
    BOOST_SCOPE_EXIT(previousTxIndex) {
        fTxIndex = previousTxIndex;
    } BOOST_SCOPE_EXIT_END
    fTxIndex = false;
    manager.SyncTransaction(*tx, pindex, 1);
    const bool hasCallback = llmq::CInstantSendManagerTestAccess::HasCallbackTransaction(manager, hash, tx, pindex);
    const bool processed = llmq::CInstantSendManagerTestAccess::ProcessPending(manager);

    BOOST_CHECK(hasCallback);
    BOOST_CHECK(processed);
    BOOST_CHECK(manager.IsLocked(tx->GetHash()));
    BOOST_CHECK(!manager.IsWaitingForTx(tx->GetHash()));
    BOOST_CHECK_EQUAL(mempool.GetTransactionsUpdated(), updates + 1);
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::RemoveConfirmed(manager, pindex->nHeight, hash));
}

BOOST_AUTO_TEST_CASE(new_pending_lock_invalidates_cached_mining_template_once)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    llmq::CInstantSendManagerTestAccess::Enable(manager);
    const auto islock = MakeLock(MakeTransaction(uint256S("1")));
    const bool previousTxIndex = fTxIndex;
    BOOST_SCOPE_EXIT(previousTxIndex) {
        fTxIndex = previousTxIndex;
    } BOOST_SCOPE_EXIT_END
    fTxIndex = true;
    const auto updates = mempool.GetTransactionsUpdated();

    llmq::CInstantSendManagerTestAccess::ProcessLock(manager, islock);
    BOOST_CHECK(manager.IsWaitingForTx(islock.txid));
    BOOST_CHECK_EQUAL(mempool.GetTransactionsUpdated(), updates + 1);
    llmq::CInstantSendManagerTestAccess::ProcessLock(manager, islock);
    BOOST_CHECK_EQUAL(mempool.GetTransactionsUpdated(), updates + 1);
}

BOOST_AUTO_TEST_CASE(chainlock_removes_descendants_across_pending_and_database)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    llmq::CInstantSendManagerTestAccess::Enable(manager);
    const auto parent = MakeLock(MakeTransaction(uint256S("1")));
    const auto child = MakeLock(MakeTransaction(parent.txid));
    const auto grandchild = MakeLock(MakeTransaction(child.txid));
    const auto unrelated = MakeLock(MakeTransaction(uint256S("2")));
    const auto parentHash = llmq::CInstantSendManagerTestAccess::AddPending(manager, parent);
    llmq::CInstantSendManagerTestAccess::WriteLock(manager, child);
    const auto grandchildHash = llmq::CInstantSendManagerTestAccess::AddPending(manager, grandchild);
    llmq::CInstantSendManagerTestAccess::AddPending(manager, unrelated);
    BOOST_REQUIRE(manager.AddPendingBlockConflict(parentHash, chainActive.Tip()));
    BOOST_REQUIRE(manager.AddPendingBlockConflict(grandchildHash, chainActive.Tip()));
    BOOST_CHECK(manager.IsBlockExcluded(chainActive.Tip()));

    manager.RemoveChainLockConflictingLock(parentHash, parent);

    llmq::CInstantSendLock result;
    for (const auto& islock : {parent, child, grandchild}) {
        BOOST_CHECK(!manager.GetInstantSendLockByHash(::SerializeHash(islock), result));
        BOOST_CHECK(!manager.IsWaitingForTx(islock.txid));
        BOOST_CHECK(!manager.IsLocked(islock.txid));
    }
    BOOST_CHECK(manager.IsWaitingForTx(unrelated.txid));
    BOOST_CHECK(!manager.IsBlockExcluded(chainActive.Tip()));
}

BOOST_AUTO_TEST_CASE(chainlocked_descendant_overrides_pending_block_exclusion)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    llmq::CInstantSendManagerTestAccess::Enable(manager);
    const auto islock = MakeLock(MakeTransaction(uint256S("1")));
    const auto hash = llmq::CInstantSendManagerTestAccess::AddPending(manager, islock);
    const uint256 rootHash = uint256S("10");
    const uint256 descendantHash = uint256S("11");
    CBlockIndex root;
    root.phashBlock = &rootHash;
    root.pprev = chainActive.Tip();
    root.nHeight = root.pprev->nHeight + 1;
    CBlockIndex descendant;
    descendant.phashBlock = &descendantHash;
    descendant.pprev = &root;
    descendant.nHeight = root.nHeight + 1;
    BOOST_REQUIRE(manager.AddPendingBlockConflict(hash, &root));
    BOOST_CHECK(manager.IsBlockExcluded(&descendant));
    BOOST_CHECK(!manager.IsBlockExcluded(chainActive.Tip()));

    llmq::CInstantSendManagerTestAccess::SetChainLock(*llmq::chainLocksHandler, &descendant);
    BOOST_CHECK(!manager.IsBlockExcluded(&root));
    BOOST_CHECK(!manager.IsBlockExcluded(&descendant));
    BOOST_CHECK(manager.IsWaitingForTx(islock.txid));
    llmq::CInstantSendManagerTestAccess::SetChainLock(*llmq::chainLocksHandler, nullptr);
}

BOOST_AUTO_TEST_CASE(unverified_locks_are_not_served)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    llmq::CInstantSendManagerTestAccess::Enable(manager);
    const auto islock = MakeLock(MakeTransaction(uint256S("1")));
    llmq::CInstantSendManagerTestAccess::AddUnverified(manager, islock);
    llmq::CInstantSendLock result;
    BOOST_CHECK(!manager.GetInstantSendLockByHash(::SerializeHash(islock), result));
}

BOOST_AUTO_TEST_CASE(mempool_conflict_callback_clears_instantsend_tracking)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    llmq::CInstantSendManagerTestAccess::Enable(manager);
    const auto tx = MakeTransaction(uint256S("1"));
    llmq::CInstantSendManagerTestAccess::TrackConflict(manager, tx);
    BOOST_REQUIRE(!llmq::CInstantSendManagerTestAccess::TrackingEmpty(manager));

    manager.SyncTransaction(*tx, nullptr, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);

    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::TrackingEmpty(manager));
}

BOOST_AUTO_TEST_CASE(pending_lock_body_cannot_be_replaced_before_completion)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    llmq::CInstantSendManagerTestAccess::Enable(manager);
    auto* previousManager = llmq::quorumInstantSendManager;
    const bool previousReplacement = fEnableReplacement;
    BOOST_SCOPE_EXIT(previousManager, previousReplacement) {
        llmq::quorumInstantSendManager = previousManager;
        fEnableReplacement = previousReplacement;
        mempool.clear();
    } BOOST_SCOPE_EXIT_END
    llmq::quorumInstantSendManager = &manager;
    fEnableReplacement = true;

    CMutableTransaction victim;
    victim.vin.emplace_back(COutPoint(uint256S("1"), 0), CScript(), 0);
    victim.vout.emplace_back(20000, CScript() << OP_DUP << OP_HASH160 <<
        std::vector<unsigned char>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG);
    const auto tx = MakeTransactionRef(victim);
    CMutableTransaction replacement(victim);
    replacement.vout[0].nValue -= 1000;

    LOCK(cs_main);
    mempool.clear();
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(tx->GetHash(), entry.FromTx(*tx));
    const auto hash = llmq::CInstantSendManagerTestAccess::AddPending(manager, MakeLock(tx));
    manager.SyncTransaction(*tx, nullptr, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    BOOST_REQUIRE(llmq::CInstantSendManagerTestAccess::HasCallbackTransaction(manager, hash, tx, nullptr));
    BOOST_REQUIRE(!manager.IsLocked(tx->GetHash()));

    CValidationState state;
    bool missingInputs = false;
    BOOST_CHECK(!AcceptToMemoryPool(mempool, state, MakeTransactionRef(replacement), false, &missingInputs));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "tx-txlock-conflict");
    BOOST_CHECK(!missingInputs);
    BOOST_CHECK(mempool.exists(tx->GetHash()));
    BOOST_CHECK(!mempool.exists(replacement.GetHash()));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(llmq_instantsend_activation_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(connect_and_pure_disconnect_refresh_feature_state)
{
    CDBWrapper database(pathTemp / "instantsend", 1 << 20, true);
    llmq::CInstantSendManager manager(database);
    auto* previousManager = llmq::quorumInstantSendManager;
    auto* parent = chainActive.Tip();
    const ActiveSporkMap parentSporks = parent->privacyData().activeDisablingSporks;
    BOOST_SCOPE_EXIT(previousManager, parent, parentSporks) {
        LOCK(cs_main);
        parent->SetActiveDisablingSporks(parentSporks);
        llmq::quorumInstantSendManager = previousManager;
    } BOOST_SCOPE_EXIT_END
    llmq::quorumInstantSendManager = &manager;
    BOOST_REQUIRE(!manager.IsNewInstantSendEnabled());

    // This fixture has no tip-notification listener, so activation must happen in validation.
    const CBlock block = CreateAndProcessBlock({}, coinbaseKey);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
    BOOST_REQUIRE(chainActive.Tip()->pprev == parent);
    BOOST_CHECK(manager.IsNewInstantSendEnabled());
    {
        LOCK(cs_main);
        parent->SetActiveDisablingSporks({{CSporkAction::featureInstantSend, {0, 0}}});
    }

    BOOST_REQUIRE(DisconnectBlocks(1));
    BOOST_CHECK(chainActive.Tip() == parent);
    BOOST_CHECK(!manager.IsNewInstantSendEnabled());
    {
        LOCK(cs_main);
        parent->SetActiveDisablingSporks(parentSporks);
    }
    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, Params()));
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK(manager.IsNewInstantSendEnabled());
}

BOOST_AUTO_TEST_SUITE_END()
