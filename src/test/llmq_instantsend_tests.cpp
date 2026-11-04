// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums_instantsend.h"
#include "masternode-sync.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "validation.h"
#include "validationinterface.h"

#include <boost/test/unit_test.hpp>

namespace llmq
{

struct CInstantSendManagerTestAccess
{
    static void SetEnabled(CInstantSendManager& manager, bool enabled)
    {
        manager.isNewInstantSendEnabled = enabled;
    }

    static bool IsTracked(CInstantSendManager& manager, const uint256& txid)
    {
        LOCK(manager.cs);
        return manager.nonLockedTxs.count(txid) > 0;
    }

    static size_t TrackedEntries(CInstantSendManager& manager)
    {
        LOCK(manager.cs);
        return manager.nonLockedTxs.size() + manager.nonLockedTxsByInputs.size();
    }
};

} // namespace llmq

BOOST_FIXTURE_TEST_SUITE(llmq_instantsend_tests, TestingSetup)

// MemPoolConflictRemovalTracker reports a TX evicted from the mempool by a conflicting mined TX with a null block
// index. InstantSend must drop it instead of treating it like a mined TX, which left it in nonLockedTxs forever.
BOOST_AUTO_TEST_CASE(conflict_evicted_tx_is_untracked)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("1"), 0);
    mtx.vin[0].scriptSig = CScript() << OP_11;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    const CTransaction tx(mtx);
    const uint256 txid = tx.GetHash();

    auto& manager = *llmq::quorumInstantSendManager;
    llmq::CInstantSendManagerTestAccess::SetEnabled(manager, true);
    masternodeSync.SwitchToNextAsset(*connman);
    masternodeSync.SwitchToNextAsset(*connman);
    BOOST_REQUIRE(masternodeSync.IsBlockchainSynced());

    // Dandelion stem phase: not in the mempool yet, but not gone either
    txpools.getStemTxPool().addUnchecked(txid, TestMemPoolEntryHelper().FromTx(tx));
    manager.SyncTransaction(tx, nullptr, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::IsTracked(manager, txid));

    // Fluffed into the mempool
    mempool.addUnchecked(txid, TestMemPoolEntryHelper().FromTx(tx));
    manager.SyncTransaction(tx, nullptr, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::IsTracked(manager, txid));

    // Evicted by a conflicting mined TX: validation reports it with no block index once it is in neither pool
    txpools.removeRecursive(tx, MemPoolRemovalReason::CONFLICT);
    BOOST_REQUIRE(!mempool.exists(txid));
    BOOST_REQUIRE(!txpools.getStemTxPool().exists(txid));
    manager.SyncTransaction(tx, nullptr, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::IsTracked(manager, txid));
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::TrackedEntries(manager), 0U);

    masternodeSync.Reset();
    llmq::CInstantSendManagerTestAccess::SetEnabled(manager, false);
}

BOOST_AUTO_TEST_SUITE_END()
