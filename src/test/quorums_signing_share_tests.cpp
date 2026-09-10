// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums_signing.h"
#include "llmq/quorums_signing_shares.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace llmq
{

struct CSigSharesVerificationTestAccess {
    static void AddPending(CSigSharesManager& manager, NodeId nodeId, const CSigShare& sigShare)
    {
        LOCK(manager.cs);
        manager.nodeStates[nodeId].pendingIncomingSigShares.Add(sigShare.GetKey(), sigShare);
    }

    static size_t PendingCount(CSigSharesManager& manager, NodeId nodeId)
    {
        LOCK(manager.cs);
        return manager.nodeStates.at(nodeId).pendingIncomingSigShares.Size();
    }

    static size_t Collect(CSigSharesManager& manager, size_t maxShares, Consensus::LLMQType llmqType, const uint256& quorumHash)
    {
        std::unordered_map<NodeId, std::vector<CSigShare> > sigSharesByNodes;
        std::unordered_map<std::pair<Consensus::LLMQType, uint256>, CQuorumCPtr, StaticSaltedHasher> quorums;
        quorums.emplace(std::make_pair(llmqType, quorumHash), CQuorumCPtr{});

        manager.CollectPendingSigSharesToVerify(maxShares, sigSharesByNodes, quorums);

        size_t count{0};
        for (const auto& p : sigSharesByNodes) {
            count += p.second.size();
        }
        return count;
    }
};

} // namespace llmq

namespace
{

llmq::CSigShare MakeSigShare(uint16_t quorumMember)
{
    llmq::CSigShare sigShare;
    sigShare.llmqType = Consensus::LLMQ_400_60;
    sigShare.quorumHash = uint256S("1");
    sigShare.quorumMember = quorumMember;
    sigShare.id = uint256S("2");
    sigShare.msgHash = uint256S("3");
    sigShare.UpdateKey();
    return sigShare;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(quorums_signing_share_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(verification_batch_is_bounded_by_share_count)
{
    constexpr NodeId nodeId{1};
    constexpr size_t maxShares{32};
    constexpr size_t totalShares{400};

    llmq::CSigSharesManager manager;
    for (uint16_t member = 0; member < totalShares; ++member) {
        llmq::CSigSharesVerificationTestAccess::AddPending(manager, nodeId, MakeSigShare(member));
    }

    const auto firstBatch = llmq::CSigSharesVerificationTestAccess::Collect(
        manager, maxShares, Consensus::LLMQ_400_60, uint256S("1"));
    BOOST_REQUIRE_EQUAL(firstBatch, maxShares);
    BOOST_CHECK_EQUAL(llmq::CSigSharesVerificationTestAccess::PendingCount(manager, nodeId), totalShares - maxShares);

    size_t collected{firstBatch};
    while (llmq::CSigSharesVerificationTestAccess::PendingCount(manager, nodeId) != 0) {
        const auto batch = llmq::CSigSharesVerificationTestAccess::Collect(
            manager, maxShares, Consensus::LLMQ_400_60, uint256S("1"));
        BOOST_REQUIRE_LE(batch, maxShares);
        BOOST_REQUIRE_GT(batch, 0U);
        collected += batch;
    }
    BOOST_CHECK_EQUAL(collected, totalShares);
}

BOOST_AUTO_TEST_SUITE_END()
