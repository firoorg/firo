// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activemasternode.h"
#include "chainparams.h"
#include "dbwrapper.h"
#include "keystore.h"
#include "llmq/quorums_instantsend.h"
#include "masternode-sync.h"
#include "script/sign.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "validation.h"
#include "validationinterface.h"

#include <boost/test/unit_test.hpp>

namespace llmq
{

/** Friend of CInstantSendManager: reaches the private state the tests set up and inspect. */
struct CInstantSendManagerTestAccess
{
    /** Flip the private InstantSend-enabled flag without a spork. */
    static void SetEnabled(CInstantSendManager& manager, bool enabled)
    {
        manager.isNewInstantSendEnabled = enabled;
    }

    /** Whether txid has a nonLockedTxs entry. */
    static bool IsTracked(CInstantSendManager& manager, const uint256& txid)
    {
        LOCK(manager.cs);
        return manager.nonLockedTxs.count(txid) > 0;
    }

    /** Entries across nonLockedTxs and nonLockedTxsByInputs; 0 means nothing leaked. */
    static size_t TrackedEntries(CInstantSendManager& manager)
    {
        LOCK(manager.cs);
        return manager.nonLockedTxs.size() + manager.nonLockedTxsByInputs.size();
    }

    /** Block index recorded for a tracked txid, nullptr while it is unmined. */
    static const CBlockIndex* MinedBlock(CInstantSendManager& manager, const uint256& txid)
    {
        LOCK(manager.cs);
        return manager.nonLockedTxs.at(txid).pindexMined;
    }

    /** Store an islock for tx so CheckCanLock accepts spends of its outputs without txindex or confirmations. */
    static void MarkParentLocked(CInstantSendManager& manager, const CTransaction& tx)
    {
        CInstantSendLock islock;
        islock.txid = tx.GetHash();
        for (const auto& input : tx.vin) {
            islock.inputs.push_back(input.prevout);
        }
        WriteLock(manager, islock, Params().GetConsensus().nInstantSendExpiryStartBlock);
    }

    /** Store islock as if it was accepted with the given lock height. Returns its hash. */
    static uint256 WriteLock(CInstantSendManager& manager, const CInstantSendLock& islock, int nLockHeight)
    {
        const uint256 hash = ::SerializeHash(islock);
        LOCK(manager.cs);
        manager.db.WriteNewInstantSendLock(hash, islock, nLockHeight);
        return hash;
    }

    static bool GetStoredLockHeight(CInstantSendManager& manager, const uint256& hash, int& nLockHeightRet)
    {
        LOCK(manager.cs);
        return manager.db.GetInstantSendLockHeight(hash, nLockHeightRet);
    }

    static bool GetLockHeight(CInstantSendManager& manager, const CInstantSendLock& islock, int& nLockHeightRet, bool& retBan)
    {
        return manager.GetLockHeight(islock, nLockHeightRet, retBan);
    }

    static void HandleExpiredLocks(CInstantSendManager& manager, const CBlockIndex* pindexNew)
    {
        manager.HandleExpiredLocks(pindexNew);
    }
};

} // namespace llmq

namespace
{

/** 100-block regtest chain with InstantSend enabled and the masternode sync marked finished; validation signals
 * are forwarded to InstantSend as firod does. */
struct InstantSendTestingSetup : TestChain100Setup, CValidationInterface
{
    const bool previousMasternodeMode{fMasternodeMode};
    const uint256 previousProTxHash{activeMasternodeInfo.proTxHash};

    /** Enable InstantSend as a non-masternode and subscribe to validation signals. */
    InstantSendTestingSetup()
    {
        fMasternodeMode = false;
        masternodeSync.Reset();
        masternodeSync.SwitchToNextAsset(*connman);
        masternodeSync.SwitchToNextAsset(*connman);
        llmq::CInstantSendManagerTestAccess::SetEnabled(*llmq::quorumInstantSendManager, true);
        RegisterValidationInterface(this);
    }

    /** Unsubscribe and restore the global masternode state. */
    ~InstantSendTestingSetup()
    {
        UnregisterValidationInterface(this);
        llmq::CInstantSendManagerTestAccess::SetEnabled(*llmq::quorumInstantSendManager, false);
        masternodeSync.Reset();
        fMasternodeMode = previousMasternodeMode;
        activeMasternodeInfo.proTxHash = previousProTxHash;
    }

    /** Feed InstantSend from validation, as CDSNotificationInterface does in firod. */
    void SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, int posInBlock) override
    {
        llmq::quorumInstantSendManager->SyncTransaction(tx, pindex, posInBlock);
    }
};

/** One input and one anyone-can-spend (OP_TRUE) output, so a child needs no signature. */
CMutableTransaction MakeTestTransaction(const COutPoint& prevout = COutPoint(uint256S("1"), 0))
{
    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    return tx;
}

/** An unsigned lock on tx's inputs: an isdlock if cycleHash is set, a legacy islock otherwise. */
llmq::CInstantSendLock MakeLock(const CTransaction& tx, const uint256& cycleHash = uint256())
{
    llmq::CInstantSendLock islock;
    if (!cycleHash.IsNull()) {
        islock.nVersion = llmq::CInstantSendLock::ISDLOCK_VERSION;
        islock.cycleHash = cycleHash;
    }
    islock.txid = tx.GetHash();
    for (const auto& input : tx.vin) {
        islock.inputs.push_back(input.prevout);
    }
    return islock;
}

/** Overrides the InstantSend expiry parameters for the scope. */
struct ScopedExpiryParams
{
    Consensus::Params& params;
    const int prevStartBlock;
    const int prevLifetime;

    ScopedExpiryParams(int startBlock, int lifetime) :
        params(const_cast<Consensus::Params&>(Params().GetConsensus())),
        prevStartBlock(params.nInstantSendExpiryStartBlock),
        prevLifetime(params.nInstantSendLockLifetime)
    {
        params.nInstantSendExpiryStartBlock = startBlock;
        params.nInstantSendLockLifetime = lifetime;
    }

    ~ScopedExpiryParams()
    {
        params.nInstantSendExpiryStartBlock = prevStartBlock;
        params.nInstantSendLockLifetime = prevLifetime;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(llmq_instantsend_tests, InstantSendTestingSetup)

/** MemPoolConflictRemovalTracker reports a TX evicted from the mempool by a conflicting mined TX with a null block
 * index. InstantSend must drop it instead of treating it like a mined TX, which left it in nonLockedTxs forever. */
BOOST_AUTO_TEST_CASE(conflict_evicted_tx_is_untracked)
{
    const CTransaction tx(MakeTestTransaction());
    const uint256 txid = tx.GetHash();

    auto& manager = *llmq::quorumInstantSendManager;
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

    // A duplicate removal notification must not recreate tracking entries.
    manager.SyncTransaction(tx, nullptr, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::TrackedEntries(manager), 0U);
}

/** A TX reported with a block index was mined, not evicted, even though it is in neither pool. */
BOOST_AUTO_TEST_CASE(mined_tx_absent_from_pools_is_tracked)
{
    const CTransaction tx(MakeTestTransaction());
    auto& manager = *llmq::quorumInstantSendManager;
    BOOST_REQUIRE(!mempool.exists(tx.GetHash()));
    BOOST_REQUIRE(!txpools.getStemTxPool().exists(tx.GetHash()));

    manager.SyncTransaction(tx, chainActive.Tip(), 0);
    BOOST_REQUIRE(llmq::CInstantSendManagerTestAccess::IsTracked(manager, tx.GetHash()));
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::MinedBlock(manager, tx.GetHash()) == chainActive.Tip());
}

/** DisconnectTip put the TX back into both pools and reports it with pprev: it stays tracked as unmined. */
BOOST_AUTO_TEST_CASE(disconnected_tx_reaccepted_into_mempool_stays_tracked)
{
    const CTransaction tx(MakeTestTransaction());
    auto& manager = *llmq::quorumInstantSendManager;
    const CBlockIndex* pindex = chainActive.Tip();
    manager.SyncTransaction(tx, pindex, 0);
    BOOST_REQUIRE(llmq::CInstantSendManagerTestAccess::IsTracked(manager, tx.GetHash()));

    txpools.getStemTxPool().addUnchecked(tx.GetHash(), TestMemPoolEntryHelper().FromTx(tx));
    mempool.addUnchecked(tx.GetHash(), TestMemPoolEntryHelper().FromTx(tx));
    manager.SyncTransaction(tx, pindex->pprev, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);

    BOOST_REQUIRE(llmq::CInstantSendManagerTestAccess::IsTracked(manager, tx.GetHash()));
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::MinedBlock(manager, tx.GetHash()) == nullptr);
}

/** DisconnectTip could not put the TX back into the pools: it is gone and must be untracked. */
BOOST_AUTO_TEST_CASE(disconnected_tx_not_reaccepted_is_untracked)
{
    const CTransaction tx(MakeTestTransaction());
    auto& manager = *llmq::quorumInstantSendManager;
    const CBlockIndex* pindex = chainActive.Tip();
    manager.SyncTransaction(tx, pindex, 0);
    BOOST_REQUIRE(llmq::CInstantSendManagerTestAccess::IsTracked(manager, tx.GetHash()));

    manager.SyncTransaction(tx, pindex->pprev, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::IsTracked(manager, tx.GetHash()));
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::TrackedEntries(manager), 0U);
}

/** Through validation: mining a conflicting TX evicts the loser, which must be untracked and must not take the
 * input vote from the mined winner. */
BOOST_AUTO_TEST_CASE(block_conflict_removal_does_not_vote_for_evicted_tx)
{
    auto& manager = *llmq::quorumInstantSendManager;
    CMutableTransaction parent = MakeTestTransaction(COutPoint(coinbaseTxns[0].GetHash(), 0));
    parent.vout[0].nValue = coinbaseTxns[0].vout[0].nValue - COIN;
    CBasicKeyStore keystore;
    keystore.AddKey(coinbaseKey);
    BOOST_REQUIRE(SignSignature(keystore, coinbaseTxns[0], parent, 0, SIGHASH_ALL));
    bool accepted = false;
    const CBlock parentBlock = CreateAndProcessBlock({parent}, coinbaseKey, &accepted);
    BOOST_REQUIRE(accepted);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == parentBlock.GetHash());

    // Seed a parent lock so input eligibility does not depend on txindex or a live quorum.
    llmq::CInstantSendManagerTestAccess::MarkParentLocked(manager, CTransaction(parent));
    CMutableTransaction loser = MakeTestTransaction(COutPoint(parent.GetHash(), 0));
    loser.vout[0].nValue = parent.vout[0].nValue - 1000;
    CMutableTransaction winner(loser);
    --winner.vout[0].nValue;
    const CTransaction losingTx(loser);
    const uint256 losingTxid = losingTx.GetHash();
    txpools.getStemTxPool().addUnchecked(losingTxid, TestMemPoolEntryHelper().Fee(1000).FromTx(losingTx));
    mempool.addUnchecked(losingTxid, TestMemPoolEntryHelper().Fee(1000).FromTx(losingTx));
    GetMainSignals().SyncTransaction(losingTx, nullptr, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    BOOST_REQUIRE(llmq::CInstantSendManagerTestAccess::IsTracked(manager, losingTxid));

    // No quorum is needed: AsyncSignIfMember records the vote before selecting one.
    // Turn on voting only after admission, so any vote for the loser comes from block eviction.
    fMasternodeMode = true;
    activeMasternodeInfo.proTxHash = uint256S("2");
    const auto llmqType = Params().GetConsensus().llmqForInstantSend;
    const uint256 inputId = ::SerializeHash(std::make_pair(std::string("inlock"), losingTx.vin[0].prevout));
    uint256 votedTxid;
    BOOST_REQUIRE(!llmq::quorumSigningManager->GetVoteForId(llmqType, inputId, votedTxid));

    const CBlock block = CreateAndProcessBlock({winner}, coinbaseKey, &accepted);
    BOOST_REQUIRE(accepted);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK(!mempool.exists(losingTxid));
    BOOST_CHECK(!txpools.getStemTxPool().exists(losingTxid));
    BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::IsTracked(manager, losingTxid));
    BOOST_REQUIRE(llmq::quorumSigningManager->GetVoteForId(llmqType, inputId, votedTxid));
    BOOST_CHECK(votedTxid == winner.GetHash());
    BOOST_REQUIRE(llmq::CInstantSendManagerTestAccess::IsTracked(manager, winner.GetHash()));
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::MinedBlock(manager, winner.GetHash()) == chainActive.Tip());
}

/** The legacy islock wire format is unchanged; the isdlock adds the version and the cycle block, and the quorum signs
 * the cycle block together with the txid. */
BOOST_AUTO_TEST_CASE(isdlock_serialization_and_sign_hash)
{
    const CTransaction tx(MakeTestTransaction());
    const llmq::CInstantSendLock legacy = MakeLock(tx);
    const llmq::CInstantSendLock isdlock = MakeLock(tx, uint256S("3"));

    CDataStream ssLegacy(SER_NETWORK, PROTOCOL_VERSION);
    ssLegacy << legacy;
    CDataStream ssLegacyExpected(SER_NETWORK, PROTOCOL_VERSION);
    ssLegacyExpected << legacy.inputs << legacy.txid << legacy.sig;
    BOOST_CHECK(ssLegacy.str() == ssLegacyExpected.str());

    CDataStream ssIsdlock(SER_NETWORK, PROTOCOL_VERSION);
    ssIsdlock << isdlock;
    CDataStream ssIsdlockExpected(SER_NETWORK, PROTOCOL_VERSION);
    ssIsdlockExpected << isdlock.nVersion << isdlock.inputs << isdlock.txid << isdlock.cycleHash << isdlock.sig;
    BOOST_CHECK(ssIsdlock.str() == ssIsdlockExpected.str());

    llmq::CInstantSendLock read;
    read.nVersion = llmq::CInstantSendLock::ISDLOCK_VERSION;
    ssIsdlock >> read;
    BOOST_CHECK(read.IsDeterministic());
    BOOST_CHECK(read.cycleHash == isdlock.cycleHash);
    BOOST_CHECK(read.txid == isdlock.txid);
    BOOST_CHECK(::SerializeHash(read) == ::SerializeHash(isdlock));
    BOOST_CHECK(::SerializeHash(read) != ::SerializeHash(legacy));

    // Both versions compete for the same request id, so at most one lock can be signed per set of inputs
    BOOST_CHECK(isdlock.GetRequestId() == legacy.GetRequestId());
    BOOST_CHECK(legacy.GetSignMsgHash() == tx.GetHash());
    BOOST_CHECK(isdlock.GetSignMsgHash() != tx.GetHash());
    BOOST_CHECK(isdlock.GetSignMsgHash() != MakeLock(tx, uint256S("4")).GetSignMsgHash());
}

/** Both versions are stored, read back from disk in their own format and carry their lock height. */
BOOST_AUTO_TEST_CASE(db_stores_both_lock_versions_with_heights)
{
    CDBWrapper dbw("", 1 << 20, true, true);
    const CTransaction tx1(MakeTestTransaction(COutPoint(uint256S("11"), 0)));
    const CTransaction tx2(MakeTestTransaction(COutPoint(uint256S("12"), 0)));
    const llmq::CInstantSendLock legacy = MakeLock(tx1);
    const llmq::CInstantSendLock isdlock = MakeLock(tx2, uint256S("3"));
    const uint256 legacyHash = ::SerializeHash(legacy);
    const uint256 isdlockHash = ::SerializeHash(isdlock);
    {
        llmq::CInstantSendDb db(dbw);
        db.WriteNewInstantSendLock(legacyHash, legacy, 600);
        db.WriteNewInstantSendLock(isdlockHash, isdlock, 48);
    }

    // A fresh instance has empty caches
    llmq::CInstantSendDb db(dbw);
    BOOST_CHECK_EQUAL(db.GetInstantSendLockCount(), 2U);

    auto readIsdlock = db.GetInstantSendLockByTxid(tx2.GetHash());
    BOOST_REQUIRE(readIsdlock);
    BOOST_CHECK(readIsdlock->IsDeterministic());
    BOOST_CHECK(readIsdlock->cycleHash == isdlock.cycleHash);
    BOOST_CHECK(::SerializeHash(*readIsdlock) == isdlockHash);

    auto readLegacy = db.GetInstantSendLockByInput(tx1.vin[0].prevout);
    BOOST_REQUIRE(readLegacy);
    BOOST_CHECK(!readLegacy->IsDeterministic());
    BOOST_CHECK(::SerializeHash(*readLegacy) == legacyHash);

    int nLockHeight = 0;
    BOOST_CHECK(db.GetInstantSendLockHeight(legacyHash, nLockHeight));
    BOOST_CHECK_EQUAL(nLockHeight, 600);
    BOOST_CHECK(db.GetInstantSendLockHeight(isdlockHash, nLockHeight));
    BOOST_CHECK_EQUAL(nLockHeight, 48);

    // Removal also drops the lock height
    CDBBatch batch(dbw);
    db.RemoveInstantSendLock(batch, isdlockHash, nullptr);
    dbw.WriteBatch(batch);
    BOOST_CHECK(!db.GetInstantSendLockByHash(isdlockHash));
    BOOST_CHECK(!db.GetInstantSendLockHeight(isdlockHash, nLockHeight));
    BOOST_CHECK(db.RemoveExpiredInstantSendLocks(100, 100).empty());
    BOOST_CHECK_EQUAL(db.GetInstantSendLockCount(), 1U);
}

/** Expired locks are removed in lock height order and archived; younger locks stay. */
BOOST_AUTO_TEST_CASE(db_removes_expired_locks)
{
    CDBWrapper dbw("", 1 << 20, true, true);
    llmq::CInstantSendDb db(dbw);
    const CTransaction tx1(MakeTestTransaction(COutPoint(uint256S("11"), 0)));
    const CTransaction tx2(MakeTestTransaction(COutPoint(uint256S("12"), 0)));
    const llmq::CInstantSendLock lock1 = MakeLock(tx1, uint256S("3"));
    const llmq::CInstantSendLock lock2 = MakeLock(tx2, uint256S("4"));
    const uint256 hash1 = ::SerializeHash(lock1);
    const uint256 hash2 = ::SerializeHash(lock2);
    db.WriteNewInstantSendLock(hash1, lock1, 10);
    db.WriteNewInstantSendLock(hash2, lock2, 20);

    BOOST_CHECK(db.RemoveExpiredInstantSendLocks(-1, 30).empty());
    BOOST_CHECK(db.RemoveExpiredInstantSendLocks(9, 30).empty());

    auto removed = db.RemoveExpiredInstantSendLocks(19, 30);
    BOOST_REQUIRE_EQUAL(removed.size(), 1U);
    BOOST_CHECK(removed.count(hash1));
    BOOST_CHECK(!db.GetInstantSendLockByHash(hash1));
    BOOST_CHECK(!db.GetInstantSendLockByTxid(tx1.GetHash()));
    BOOST_CHECK(!db.GetInstantSendLockByInput(tx1.vin[0].prevout));
    BOOST_CHECK(db.HasArchivedInstantSendLock(hash1));
    int nLockHeight;
    BOOST_CHECK(!db.GetInstantSendLockHeight(hash1, nLockHeight));
    BOOST_CHECK(db.GetInstantSendLockByTxid(tx2.GetHash()));

    // Nothing is left behind on disk either
    llmq::CInstantSendDb freshDb(dbw);
    BOOST_CHECK(!freshDb.GetInstantSendLockByTxid(tx1.GetHash()));
    BOOST_CHECK(!freshDb.GetInstantSendLockByInput(tx1.vin[0].prevout));
    BOOST_CHECK(freshDb.GetInstantSendLockByTxid(tx2.GetHash()));

    removed = db.RemoveExpiredInstantSendLocks(20, 30);
    BOOST_REQUIRE_EQUAL(removed.size(), 1U);
    BOOST_CHECK(removed.count(hash2));
    BOOST_CHECK_EQUAL(db.GetInstantSendLockCount(), 0U);
}

/** Removing an older duplicate lock for a TX must not unlink the TX and its inputs from the newer lock. */
BOOST_AUTO_TEST_CASE(db_removing_duplicate_keeps_newer_lock)
{
    CDBWrapper dbw("", 1 << 20, true, true);
    llmq::CInstantSendDb db(dbw);
    const CTransaction tx(MakeTestTransaction());
    const llmq::CInstantSendLock older = MakeLock(tx, uint256S("3"));
    const llmq::CInstantSendLock newer = MakeLock(tx, uint256S("4"));
    db.WriteNewInstantSendLock(::SerializeHash(older), older, 10);
    db.WriteNewInstantSendLock(::SerializeHash(newer), newer, 20);

    BOOST_REQUIRE_EQUAL(db.RemoveExpiredInstantSendLocks(10, 30).size(), 1U);
    auto byTxid = db.GetInstantSendLockByTxid(tx.GetHash());
    BOOST_REQUIRE(byTxid);
    BOOST_CHECK(byTxid->cycleHash == newer.cycleHash);
    BOOST_CHECK(db.GetInstantSendLockByInput(tx.vin[0].prevout));
}

/** Locks stored by an older version have no lock height. The manager records the expiry activation height for them
 * on startup, so they expire together a lifetime after activation. */
BOOST_AUTO_TEST_CASE(legacy_locks_get_activation_height_on_startup)
{
    CDBWrapper dbw("", 1 << 20, true, true);
    const CTransaction tx(MakeTestTransaction());
    const llmq::CInstantSendLock legacy = MakeLock(tx);
    const uint256 hash = ::SerializeHash(legacy);
    // Written the way older versions did, without a lock height
    dbw.Write(std::make_tuple(std::string("is_i"), hash), legacy);
    dbw.Write(std::make_tuple(std::string("is_tx"), legacy.txid), hash);
    dbw.Write(std::make_tuple(std::string("is_in"), legacy.inputs[0]), hash);

    const int nStartBlock = Params().GetConsensus().nInstantSendExpiryStartBlock;
    llmq::CInstantSendManager manager(dbw);
    {
        llmq::CInstantSendDb db(dbw);
        int nLockHeight = 0;
        BOOST_REQUIRE(db.GetInstantSendLockHeight(hash, nLockHeight));
        BOOST_CHECK_EQUAL(nLockHeight, nStartBlock);
        BOOST_CHECK(db.RemoveExpiredInstantSendLocks(nStartBlock - 1, nStartBlock).empty());
        BOOST_CHECK_EQUAL(db.RemoveExpiredInstantSendLocks(nStartBlock, nStartBlock).size(), 1U);
        BOOST_CHECK(!db.GetInstantSendLockByTxid(tx.GetHash()));
    }
}

/** Lock heights: the activation height for legacy locks, the cycle block's height for isdlocks. Locks that are
 * expired for the next block, or point to a block that can't be a cycle start, are not accepted. */
BOOST_AUTO_TEST_CASE(lock_height_of_received_locks)
{
    auto& manager = *llmq::quorumInstantSendManager;
    const auto& consensus = Params().GetConsensus();
    const int dkgInterval = consensus.llmqs.at(consensus.llmqForInstantSend).dkgInterval;
    const CTransaction tx(MakeTestTransaction());
    const int nTipHeight = chainActive.Height();
    const int nCycleHeight = nTipHeight - nTipHeight % dkgInterval;
    BOOST_REQUIRE(nCycleHeight > 0);

    int nLockHeight = -1;
    bool fBan = true;
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::GetLockHeight(manager, MakeLock(tx), nLockHeight, fBan));
    BOOST_CHECK_EQUAL(nLockHeight, consensus.nInstantSendExpiryStartBlock);
    BOOST_CHECK(!fBan);

    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::GetLockHeight(manager, MakeLock(tx, chainActive[nCycleHeight]->GetBlockHash()), nLockHeight, fBan));
    BOOST_CHECK_EQUAL(nLockHeight, nCycleHeight);
    BOOST_CHECK(!fBan);

    BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::GetLockHeight(manager, MakeLock(tx, chainActive[nCycleHeight + 1]->GetBlockHash()), nLockHeight, fBan));
    BOOST_CHECK(fBan);

    BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::GetLockHeight(manager, MakeLock(tx, uint256S("5")), nLockHeight, fBan));
    BOOST_CHECK(!fBan);

    {
        // The cycle start before the current one expires with the next block, the current one doesn't
        const int nLifetime = nTipHeight + 1 - (nCycleHeight - dkgInterval);
        ScopedExpiryParams expiry(consensus.nInstantSendExpiryStartBlock, nLifetime);
        BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::GetLockHeight(manager, MakeLock(tx, chainActive[nCycleHeight - dkgInterval]->GetBlockHash()), nLockHeight, fBan));
        BOOST_CHECK(!fBan);
        BOOST_CHECK(llmq::CInstantSendManagerTestAccess::GetLockHeight(manager, MakeLock(tx, chainActive[nCycleHeight]->GetBlockHash()), nLockHeight, fBan));
    }
    {
        // Legacy locks are not accepted anymore once a lifetime has passed since activation
        ScopedExpiryParams expiry(nTipHeight + 1 - 50, 50);
        BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::GetLockHeight(manager, MakeLock(tx), nLockHeight, fBan));
        BOOST_CHECK(!fBan);
    }
}

/** A lock stops conflicting with spends of its inputs at lock height + lifetime, even before it is removed. */
BOOST_AUTO_TEST_CASE(conflicting_lock_expires_after_lifetime)
{
    auto& manager = *llmq::quorumInstantSendManager;
    const int nLifetime = Params().GetConsensus().nInstantSendLockLifetime;
    const CTransaction locked(MakeTestTransaction());
    CMutableTransaction conflicting = MakeTestTransaction();
    conflicting.vout[0].nValue = 2;
    const CTransaction conflictingTx(conflicting);
    llmq::CInstantSendManagerTestAccess::WriteLock(manager, MakeLock(locked, uint256S("3")), 50);

    BOOST_CHECK(manager.GetConflictingLock(conflictingTx));
    BOOST_CHECK(manager.GetConflictingLock(conflictingTx, 50 + nLifetime - 1));
    BOOST_CHECK(!manager.GetConflictingLock(conflictingTx, 50 + nLifetime));
    BOOST_CHECK(!manager.GetConflictingLock(locked, 50));
}

/** A new tip removes the locks that are expired for the next block and archives them. */
BOOST_AUTO_TEST_CASE(new_tip_removes_expired_locks)
{
    auto& manager = *llmq::quorumInstantSendManager;
    const int nLifetime = Params().GetConsensus().nInstantSendLockLifetime;
    const CTransaction tx1(MakeTestTransaction(COutPoint(uint256S("11"), 0)));
    const CTransaction tx2(MakeTestTransaction(COutPoint(uint256S("12"), 0)));
    const uint256 hash1 = llmq::CInstantSendManagerTestAccess::WriteLock(manager, MakeLock(tx1, uint256S("3")), 50);
    const uint256 hash2 = llmq::CInstantSendManagerTestAccess::WriteLock(manager, MakeLock(tx2, uint256S("4")), 51);

    CBlockIndex tip;
    tip.nHeight = 50 + nLifetime - 2;
    llmq::CInstantSendManagerTestAccess::HandleExpiredLocks(manager, &tip);
    BOOST_CHECK(manager.IsLocked(tx1.GetHash()));
    BOOST_CHECK(manager.IsLocked(tx2.GetHash()));

    tip.nHeight = 50 + nLifetime - 1;
    llmq::CInstantSendManagerTestAccess::HandleExpiredLocks(manager, &tip);
    BOOST_CHECK(!manager.IsLocked(tx1.GetHash()));
    BOOST_CHECK(manager.IsLocked(tx2.GetHash()));
    BOOST_CHECK(manager.AlreadyHave(CInv(MSG_ISDLOCK, hash1)));
    int nLockHeight;
    BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::GetStoredLockHeight(manager, hash1, nLockHeight));
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::GetStoredLockHeight(manager, hash2, nLockHeight));
    BOOST_CHECK_EQUAL(nLockHeight, 51);
}

BOOST_AUTO_TEST_SUITE_END()
