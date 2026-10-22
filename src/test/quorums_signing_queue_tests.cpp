// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dbwrapper.h"
#include "llmq/quorums_signing.h"
#include "llmq/quorums_signing_shares.h"
#include "test/test_bitcoin.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <thread>
#include <vector>

namespace llmq
{

struct CSigningManagerTestAccess
{
    static void Push(CSigningManager& manager, NodeId from, const CRecoveredSig& recoveredSig)
    {
        manager.PushPendingRecoveredSig(from, recoveredSig);
    }

    static size_t Count(CSigningManager& manager)
    {
        LOCK(manager.cs);
        size_t count = 0;
        for (const auto& nodeEntry : manager.pendingRecoveredSigs) {
            count += nodeEntry.second.size();
        }
        return count;
    }

    static size_t Count(CSigningManager& manager, NodeId nodeId)
    {
        LOCK(manager.cs);
        auto it = manager.pendingRecoveredSigs.find(nodeId);
        return it == manager.pendingRecoveredSigs.end() ? 0 : it->second.size();
    }

    static size_t TrackedCount(CSigningManager& manager)
    {
        LOCK(manager.cs);
        return manager.pendingRecoveredSigsCount;
    }

    static bool HasNode(CSigningManager& manager, NodeId nodeId)
    {
        LOCK(manager.cs);
        return manager.pendingRecoveredSigs.count(nodeId) != 0;
    }

    static void DrainKnown(CSigningManager& manager, const CRecoveredSig& recoveredSig)
    {
        manager.db.WriteRecoveredSig(recoveredSig);
        std::unordered_map<NodeId, std::list<CRecoveredSig>> recoveredSigsByNode;
        std::unordered_map<std::pair<Consensus::LLMQType, uint256>, CQuorumCPtr, StaticSaltedHasher> quorums;
        manager.CollectPendingRecoveredSigsToVerify(1, recoveredSigsByNode, quorums);
    }
};

} // namespace llmq

namespace
{

struct SigningQueueSetup : BasicTestingSetup
{
    CDBWrapper db;
    llmq::CSigningManager manager;
    llmq::CRecoveredSig recoveredSig{};

    SigningQueueSetup() : db(boost::filesystem::temp_directory_path() / boost::filesystem::unique_path(), 1 << 20, true, false),
                          manager(db, true)
    {
    }
};

struct ScopedSigningManager
{
    llmq::CSigningManager* previous;

    explicit ScopedSigningManager(llmq::CSigningManager* manager) :
        previous(llmq::quorumSigningManager)
    {
        llmq::quorumSigningManager = manager;
    }

    ~ScopedSigningManager()
    {
        llmq::quorumSigningManager = previous;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(quorums_signing_queue_tests, SigningQueueSetup)

BOOST_AUTO_TEST_CASE(pending_recovered_sig_limits)
{
    for (size_t i = 0; i < llmq::MAX_PENDING_RECSIGS_PER_NODE + 1; ++i) {
        llmq::CSigningManagerTestAccess::Push(manager, 1, recoveredSig);
    }
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::Count(manager, 1), llmq::MAX_PENDING_RECSIGS_PER_NODE);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::TrackedCount(manager), llmq::MAX_PENDING_RECSIGS_PER_NODE);

    llmq::CSigningManager globalManager(db, true);
    constexpr NodeId nodesAtGlobalLimit = llmq::MAX_PENDING_RECSIGS_TOTAL / llmq::MAX_PENDING_RECSIGS_PER_NODE;
    for (NodeId nodeId = 0; nodeId < nodesAtGlobalLimit; ++nodeId) {
        for (size_t i = 0; i < llmq::MAX_PENDING_RECSIGS_PER_NODE; ++i) {
            llmq::CSigningManagerTestAccess::Push(globalManager, nodeId, recoveredSig);
        }
    }
    llmq::CSigningManagerTestAccess::Push(globalManager, nodesAtGlobalLimit, recoveredSig);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::Count(globalManager), llmq::MAX_PENDING_RECSIGS_TOTAL);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::TrackedCount(globalManager), llmq::MAX_PENDING_RECSIGS_TOTAL);
    BOOST_CHECK(!llmq::CSigningManagerTestAccess::HasNode(globalManager, nodesAtGlobalLimit));

    globalManager.RemoveNodesIf([](NodeId nodeId) {
        return nodeId == 0;
    });
    llmq::CSigningManagerTestAccess::Push(globalManager, nodesAtGlobalLimit, recoveredSig);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::Count(globalManager), llmq::MAX_PENDING_RECSIGS_TOTAL - llmq::MAX_PENDING_RECSIGS_PER_NODE + 1);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::TrackedCount(globalManager), llmq::MAX_PENDING_RECSIGS_TOTAL - llmq::MAX_PENDING_RECSIGS_PER_NODE + 1);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::Count(globalManager, nodesAtGlobalLimit), 1U);
}

BOOST_AUTO_TEST_CASE(pending_recovered_sig_limit_is_concurrent)
{
    constexpr NodeId nodeCount = 12;
    constexpr size_t attemptsPerNode = 1200;
    std::vector<std::thread> threads;
    threads.reserve(nodeCount);

    for (NodeId nodeId = 0; nodeId < nodeCount; ++nodeId) {
        threads.emplace_back([&, nodeId] {
            for (size_t i = 0; i < attemptsPerNode; ++i) {
                llmq::CSigningManagerTestAccess::Push(manager, nodeId, recoveredSig);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }

    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::Count(manager), llmq::MAX_PENDING_RECSIGS_TOTAL);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::TrackedCount(manager), llmq::MAX_PENDING_RECSIGS_TOTAL);
    for (NodeId nodeId = 0; nodeId < nodeCount; ++nodeId) {
        BOOST_CHECK_LE(llmq::CSigningManagerTestAccess::Count(manager, nodeId), llmq::MAX_PENDING_RECSIGS_PER_NODE);
    }
}

BOOST_AUTO_TEST_CASE(pending_recovered_sigs_are_removed_when_banned)
{
    llmq::CSigningManagerTestAccess::Push(manager, 1, recoveredSig);
    llmq::CSigningManagerTestAccess::Push(manager, 2, recoveredSig);

    ScopedSigningManager scopedSigningManager(&manager);
    llmq::CSigSharesManager sigSharesManager;
    {
        LOCK(cs_main);
        sigSharesManager.MarkNodeBanned(1);
    }

    BOOST_CHECK(!llmq::CSigningManagerTestAccess::HasNode(manager, 1));
    BOOST_CHECK(llmq::CSigningManagerTestAccess::HasNode(manager, 2));
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::Count(manager), 1U);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::TrackedCount(manager), 1U);
}

BOOST_AUTO_TEST_CASE(pending_recovered_sig_drain_prunes_node)
{
    recoveredSig.UpdateHash();
    llmq::CSigningManagerTestAccess::Push(manager, 1, recoveredSig);

    llmq::CSigningManagerTestAccess::DrainKnown(manager, recoveredSig);

    BOOST_CHECK(!llmq::CSigningManagerTestAccess::HasNode(manager, 1));
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::Count(manager), 0U);
    BOOST_CHECK_EQUAL(llmq::CSigningManagerTestAccess::TrackedCount(manager), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
