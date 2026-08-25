// Copyright (c) 2026 The Dash Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums_signing_shares.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace llmq
{
namespace
{
uint256 TestHash(uint32_t value)
{
    uint256 hash;
    hash.SetHex(strprintf("%064x", value));
    return hash;
}

CSigSesAnn MakeAnn(Consensus::LLMQType llmqType, uint32_t uniqueValue)
{
    CSigSesAnn ann;
    ann.sessionId = uniqueValue;
    ann.llmqType = llmqType;
    ann.quorumHash = TestHash(1);
    ann.id = TestHash(uniqueValue + 100);
    ann.msgHash = TestHash(uniqueValue + 200);
    return ann;
}

CSigShare MakeShare(Consensus::LLMQType llmqType, uint32_t uniqueValue)
{
    CSigShare share;
    share.llmqType = llmqType;
    share.quorumHash = TestHash(1);
    share.quorumMember = 0;
    share.id = TestHash(uniqueValue + 100);
    share.msgHash = TestHash(uniqueValue + 200);
    share.UpdateKey();
    return share;
}
}

BOOST_FIXTURE_TEST_SUITE(llmq_signing_shares_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(session_announcement_limit_allows_known_session)
{
    constexpr size_t maxSessions{2};
    CSigSharesNodeState nodeState;
    auto ann1 = MakeAnn(Consensus::LLMQ_50_60, 1);
    auto ann2 = MakeAnn(Consensus::LLMQ_50_60, 2);
    const auto ann3 = MakeAnn(Consensus::LLMQ_50_60, 3);

    BOOST_CHECK(nodeState.CanCreateSessionFromAnn(ann1, maxSessions));
    nodeState.GetOrCreateSessionFromAnn(ann1);
    BOOST_CHECK(nodeState.CanCreateSessionFromAnn(ann2, maxSessions));
    nodeState.GetOrCreateSessionFromAnn(ann2);

    BOOST_CHECK_EQUAL(nodeState.GetAnnouncementSessionCount(Consensus::LLMQ_50_60), maxSessions);
    BOOST_CHECK(!nodeState.CanCreateSessionFromAnn(ann3, maxSessions));

    ann1.sessionId = 4;
    BOOST_CHECK(nodeState.CanCreateSessionFromAnn(ann1, maxSessions));
    nodeState.GetOrCreateSessionFromAnn(ann1);
    BOOST_CHECK_EQUAL(nodeState.GetSessionCount(), maxSessions);
}

BOOST_AUTO_TEST_CASE(send_only_sessions_do_not_count_toward_announcement_limit)
{
    constexpr size_t maxSessions{1};
    CSigSharesNodeState nodeState;
    const auto share = MakeShare(Consensus::LLMQ_50_60, 1);
    const auto ann1 = MakeAnn(Consensus::LLMQ_50_60, 2);
    const auto ann2 = MakeAnn(Consensus::LLMQ_50_60, 3);

    nodeState.GetOrCreateSessionFromShare(share);
    BOOST_CHECK_EQUAL(nodeState.GetSessionCount(Consensus::LLMQ_50_60), 1U);
    BOOST_CHECK_EQUAL(nodeState.GetAnnouncementSessionCount(Consensus::LLMQ_50_60), 0U);

    BOOST_CHECK(nodeState.CanCreateSessionFromAnn(ann1, maxSessions));
    nodeState.GetOrCreateSessionFromAnn(ann1);
    BOOST_CHECK(!nodeState.CanCreateSessionFromAnn(ann2, maxSessions));
    BOOST_CHECK_EQUAL(nodeState.GetSessionCount(), 2U);
}

BOOST_AUTO_TEST_CASE(session_announcement_limit_is_per_llmq_type)
{
    constexpr size_t maxSessions{1};
    CSigSharesNodeState nodeState;
    const auto typeOneAnn1 = MakeAnn(Consensus::LLMQ_50_60, 1);
    const auto typeOneAnn2 = MakeAnn(Consensus::LLMQ_50_60, 2);
    const auto typeTwoAnn = MakeAnn(Consensus::LLMQ_400_60, 3);

    nodeState.GetOrCreateSessionFromAnn(typeOneAnn1);
    BOOST_CHECK(!nodeState.CanCreateSessionFromAnn(typeOneAnn2, maxSessions));
    BOOST_CHECK(nodeState.CanCreateSessionFromAnn(typeTwoAnn, maxSessions));
    nodeState.GetOrCreateSessionFromAnn(typeTwoAnn);

    BOOST_CHECK_EQUAL(nodeState.GetAnnouncementSessionCount(Consensus::LLMQ_50_60), 1U);
    BOOST_CHECK_EQUAL(nodeState.GetAnnouncementSessionCount(Consensus::LLMQ_400_60), 1U);
    BOOST_CHECK_EQUAL(nodeState.GetSessionCount(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
}
