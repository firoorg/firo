// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activemasternode.h"
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

    static const CBlockIndex* MinedBlock(CInstantSendManager& manager, const uint256& txid)
    {
        LOCK(manager.cs);
        return manager.nonLockedTxs.at(txid).pindexMined;
    }

    static void MarkParentLocked(CInstantSendManager& manager, const CTransaction& tx)
    {
        CInstantSendLock islock;
        islock.txid = tx.GetHash();
        for (const auto& input : tx.vin) {
            islock.inputs.push_back(input.prevout);
        }
        LOCK(manager.cs);
        manager.db.WriteNewInstantSendLock(::SerializeHash(islock), islock);
    }
};

} // namespace llmq

namespace
{

struct InstantSendTestingSetup : TestChain100Setup, CValidationInterface
{
    const bool previousMasternodeMode{fMasternodeMode};
    const uint256 previousProTxHash{activeMasternodeInfo.proTxHash};

    InstantSendTestingSetup()
    {
        fMasternodeMode = false;
        masternodeSync.Reset();
        masternodeSync.SwitchToNextAsset(*connman);
        masternodeSync.SwitchToNextAsset(*connman);
        llmq::CInstantSendManagerTestAccess::SetEnabled(*llmq::quorumInstantSendManager, true);
        RegisterValidationInterface(this);
    }

    ~InstantSendTestingSetup()
    {
        UnregisterValidationInterface(this);
        llmq::CInstantSendManagerTestAccess::SetEnabled(*llmq::quorumInstantSendManager, false);
        masternodeSync.Reset();
        fMasternodeMode = previousMasternodeMode;
        activeMasternodeInfo.proTxHash = previousProTxHash;
    }

    void SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, int posInBlock) override
    {
        llmq::quorumInstantSendManager->SyncTransaction(tx, pindex, posInBlock);
    }
};

CMutableTransaction MakeTestTransaction(const COutPoint& prevout = COutPoint(uint256S("1"), 0))
{
    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    return tx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(llmq_instantsend_tests, InstantSendTestingSetup)

// MemPoolConflictRemovalTracker reports a TX evicted from the mempool by a conflicting mined TX with a null block
// index. InstantSend must drop it instead of treating it like a mined TX, which left it in nonLockedTxs forever.
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

BOOST_AUTO_TEST_SUITE_END()
