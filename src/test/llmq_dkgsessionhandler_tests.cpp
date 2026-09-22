// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums_dkgsessionhandler.h"

#include <boost/test/unit_test.hpp>

namespace llmq
{

BOOST_AUTO_TEST_SUITE(llmq_dkgsessionhandler_tests)

BOOST_AUTO_TEST_CASE(detect_mixed_message_peers)
{
    using Message = std::pair<NodeId, std::shared_ptr<int>>;
    const std::vector<Message> singlePeer{{101, nullptr}, {101, nullptr}};
    const std::vector<Message> mixedPeers{{101, nullptr}, {101, nullptr}, {202, nullptr}};

    BOOST_CHECK(detail::BatchNodeIdsAllSame(singlePeer));
    BOOST_CHECK(!detail::BatchNodeIdsAllSame(mixedPeers));
}

BOOST_AUTO_TEST_SUITE_END()

}
