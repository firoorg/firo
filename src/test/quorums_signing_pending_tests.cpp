// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums_signing.h"
#include "llmq/quorums_signing_shares.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace llmq
{

struct CSigSharesManagerTestAccess {
    static bool AddPending(CSigSharesManager& manager, NodeId nodeId, const CSigShare& sigShare)
    {
        LOCK(manager.cs);
        auto& nodeState = manager.nodeStates[nodeId];
        return manager.TryAddPendingIncomingSigShare(nodeId, nodeState, sigShare);
    }

    static void ErasePending(CSigSharesManager& manager, NodeId nodeId, const SigShareKey& key)
    {
        LOCK(manager.cs);
        manager.nodeStates.at(nodeId).pendingIncomingSigShares.Erase(key);
    }

    static size_t PendingCount(CSigSharesManager& manager, NodeId nodeId)
    {
        LOCK(manager.cs);
        return manager.nodeStates.at(nodeId).pendingIncomingSigShares.Size();
    }

    static size_t PendingTotal(CSigSharesManager& manager)
    {
        LOCK(manager.cs);
        size_t total{0};
        for (const auto& p : manager.nodeStates) {
            total += p.second.pendingIncomingSigShares.Size();
        }
        return total;
    }

    static bool IsBanned(CSigSharesManager& manager, NodeId nodeId)
    {
        LOCK(manager.cs);
        return manager.nodeStates.at(nodeId).banned;
    }

    static constexpr size_t MaxPerNode()
    {
        return CSigSharesManager::MAX_PENDING_SIG_SHARES_PER_NODE;
    }

    static constexpr size_t MaxTotal()
    {
        return CSigSharesManager::MAX_PENDING_SIG_SHARES_TOTAL;
    }
};

} // namespace llmq

namespace
{

uint256 HashFromNonce(size_t nonce)
{
    return uint256S(strprintf("%064x", static_cast<unsigned int>(nonce)));
}

llmq::CSigShare MakeSigShare(size_t nonce, uint16_t quorumMember = 0)
{
    llmq::CSigShare sigShare;
    sigShare.llmqType = Consensus::LLMQ_50_60;
    sigShare.quorumHash = HashFromNonce(1);
    sigShare.quorumMember = quorumMember;
    sigShare.id = HashFromNonce(nonce + 2);
    sigShare.msgHash = HashFromNonce(nonce + 3);
    sigShare.UpdateKey();
    return sigShare;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(quorums_signing_pending_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sig_share_map_size_tracks_mutations)
{
    llmq::SigShareMap<llmq::CSigShare> sigShares;
    const auto sigShare1 = MakeSigShare(1);
    const auto sigShare2 = MakeSigShare(2);

    BOOST_CHECK(sigShares.Add(sigShare1.GetKey(), sigShare1));
    BOOST_CHECK(!sigShares.Add(sigShare1.GetKey(), sigShare1));
    BOOST_CHECK(sigShares.Add(sigShare2.GetKey(), sigShare2));
    BOOST_CHECK_EQUAL(sigShares.Size(), 2U);

    sigShares.Erase(sigShare1.GetKey());
    sigShares.Erase(sigShare1.GetKey());
    BOOST_CHECK_EQUAL(sigShares.Size(), 1U);

    sigShares.EraseAllForSignHash(sigShare2.GetSignHash());
    BOOST_CHECK(sigShares.Empty());
    BOOST_CHECK_EQUAL(sigShares.Size(), 0U);

    BOOST_CHECK(sigShares.Add(sigShare1.GetKey(), sigShare1));
    BOOST_CHECK(sigShares.Add(sigShare2.GetKey(), sigShare2));
    sigShares.EraseIf([&](const llmq::SigShareKey& key, const llmq::CSigShare&) {
        return key == sigShare1.GetKey();
    });
    BOOST_CHECK_EQUAL(sigShares.Size(), 1U);

    sigShares.Clear();
    BOOST_CHECK(sigShares.Empty());
    BOOST_CHECK_EQUAL(sigShares.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(sig_share_map_bucket_erase_updates_size)
{
    llmq::SigShareMap<llmq::CSigShare> sigShares;
    const auto signHash = MakeSigShare(1).GetSignHash();

    for (uint16_t member = 0; member < 5; ++member) {
        const auto sigShare = MakeSigShare(1, member);
        BOOST_CHECK(sigShare.GetSignHash() == signHash);
        BOOST_CHECK(sigShares.Add(sigShare.GetKey(), sigShare));
    }
    BOOST_CHECK_EQUAL(sigShares.Size(), 5U);

    sigShares.EraseAllForSignHash(signHash);
    BOOST_CHECK(sigShares.Empty());
    BOOST_CHECK_EQUAL(sigShares.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(pending_sig_shares_session_removal_updates_count)
{
    llmq::CSigSharesNodeState nodeState;
    const auto sigShare1 = MakeSigShare(1);
    const auto sigShare2 = MakeSigShare(2);

    BOOST_CHECK(nodeState.pendingIncomingSigShares.Add(sigShare1.GetKey(), sigShare1));
    BOOST_CHECK(nodeState.pendingIncomingSigShares.Add(sigShare2.GetKey(), sigShare2));
    BOOST_CHECK_EQUAL(nodeState.pendingIncomingSigShares.Size(), 2U);

    nodeState.RemoveSession(sigShare1.GetSignHash());
    BOOST_CHECK_EQUAL(nodeState.pendingIncomingSigShares.Size(), 1U);
    BOOST_CHECK(!nodeState.pendingIncomingSigShares.Has(sigShare1.GetKey()));
    BOOST_CHECK(nodeState.pendingIncomingSigShares.Has(sigShare2.GetKey()));

    nodeState.RemoveSession(sigShare1.GetSignHash());
    nodeState.RemoveSession(MakeSigShare(3).GetSignHash());
    BOOST_CHECK_EQUAL(nodeState.pendingIncomingSigShares.Size(), 1U);
}

BOOST_AUTO_TEST_CASE(pending_incoming_sig_shares_are_bounded)
{
    constexpr NodeId firstNode{1};
    const size_t maxPerNode = llmq::CSigSharesManagerTestAccess::MaxPerNode();
    const size_t maxTotal = llmq::CSigSharesManagerTestAccess::MaxTotal();

    llmq::CSigSharesManager perNodeManager;
    bool admittedAll{true};
    for (size_t i = 0; i < maxPerNode; ++i) {
        admittedAll &= llmq::CSigSharesManagerTestAccess::AddPending(perNodeManager, firstNode, MakeSigShare(i));
    }
    BOOST_REQUIRE(admittedAll);
    BOOST_CHECK_EQUAL(llmq::CSigSharesManagerTestAccess::PendingCount(perNodeManager, firstNode), maxPerNode);

    const auto excessPerNode = MakeSigShare(maxPerNode);
    BOOST_CHECK(!llmq::CSigSharesManagerTestAccess::AddPending(perNodeManager, firstNode, excessPerNode));
    BOOST_CHECK_EQUAL(llmq::CSigSharesManagerTestAccess::PendingCount(perNodeManager, firstNode), maxPerNode);

    const auto firstSigShare = MakeSigShare(0);
    llmq::CSigSharesManagerTestAccess::ErasePending(perNodeManager, firstNode, firstSigShare.GetKey());
    BOOST_CHECK(llmq::CSigSharesManagerTestAccess::AddPending(perNodeManager, firstNode, excessPerNode));
    BOOST_CHECK_EQUAL(llmq::CSigSharesManagerTestAccess::PendingCount(perNodeManager, firstNode), maxPerNode);

    perNodeManager.MarkNodeBanned(firstNode);
    BOOST_CHECK(llmq::CSigSharesManagerTestAccess::IsBanned(perNodeManager, firstNode));
    BOOST_CHECK_EQUAL(llmq::CSigSharesManagerTestAccess::PendingCount(perNodeManager, firstNode), 0U);
    BOOST_CHECK(!llmq::CSigSharesManagerTestAccess::AddPending(perNodeManager, firstNode, MakeSigShare(maxPerNode + 1)));

    llmq::CSigSharesManager globalManager;
    admittedAll = true;
    for (size_t i = 0; i < maxTotal; ++i) {
        const NodeId nodeId = static_cast<NodeId>(100 + i / maxPerNode);
        admittedAll &= llmq::CSigSharesManagerTestAccess::AddPending(globalManager, nodeId, MakeSigShare(10000 + i));
    }
    BOOST_REQUIRE(admittedAll);
    BOOST_CHECK_EQUAL(llmq::CSigSharesManagerTestAccess::PendingTotal(globalManager), maxTotal);

    constexpr NodeId excessNode{1000};
    const auto excessGlobal = MakeSigShare(10000 + maxTotal);
    BOOST_CHECK(!llmq::CSigSharesManagerTestAccess::AddPending(globalManager, excessNode, excessGlobal));
    BOOST_CHECK_EQUAL(llmq::CSigSharesManagerTestAccess::PendingTotal(globalManager), maxTotal);

    const auto globalFirstSigShare = MakeSigShare(10000);
    llmq::CSigSharesManagerTestAccess::ErasePending(globalManager, 100, globalFirstSigShare.GetKey());
    BOOST_CHECK(llmq::CSigSharesManagerTestAccess::AddPending(globalManager, excessNode, excessGlobal));
    BOOST_CHECK_EQUAL(llmq::CSigSharesManagerTestAccess::PendingTotal(globalManager), maxTotal);
}

BOOST_AUTO_TEST_SUITE_END()
