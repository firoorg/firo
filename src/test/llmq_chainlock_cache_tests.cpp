// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums_chainlocks.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace llmq
{

struct CChainLocksHandlerTestAccess
{
    static size_t SeenCount(CChainLocksHandler& handler)
    {
        LOCK(handler.cs);
        return handler.seenChainLocks.size();
    }

    static bool SetSeenTime(CChainLocksHandler& handler, const uint256& hash, int64_t time)
    {
        LOCK(handler.cs);
        auto it = handler.seenChainLocks.find(hash);
        if (it == handler.seenChainLocks.end()) {
            return false;
        }
        handler.seenChainLocks.update(it, time);
        return true;
    }

    static void SetBest(CChainLocksHandler& handler, const CChainLockSig& clsig, const uint256& hash)
    {
        LOCK(handler.cs);
        handler.bestChainLock = clsig;
        handler.bestChainLockHash = hash;
    }
};

} // namespace llmq

BOOST_FIXTURE_TEST_SUITE(llmq_chainlock_cache_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(stale_chainlock_cache_is_bounded)
{
    constexpr size_t MAX_SEEN_CHAINLOCKS{1024};

    llmq::CChainLockSig bestChainLock;
    bestChainLock.nHeight = 100;
    bestChainLock.blockHash = uint256S("1");
    const uint256 bestHash = ::SerializeHash(bestChainLock);
    llmq::CChainLocksHandlerTestAccess::SetBest(*llmq::chainLocksHandler, bestChainLock, bestHash);

    BOOST_CHECK(llmq::chainLocksHandler->AlreadyHave(CInv(MSG_CLSIG, bestHash)));

    uint256 firstStaleHash;
    std::vector<uint256> recentStaleHashes;
    for (size_t i = 0; i <= MAX_SEEN_CHAINLOCKS; ++i) {
        llmq::CChainLockSig staleChainLock;
        staleChainLock.nHeight = bestChainLock.nHeight;
        staleChainLock.blockHash = uint256S(strprintf("%064x", static_cast<unsigned int>(i + 2)));
        const uint256 hash = ::SerializeHash(staleChainLock);
        if (i == 0) {
            firstStaleHash = hash;
        }
        if (i >= MAX_SEEN_CHAINLOCKS - 1) {
            recentStaleHashes.emplace_back(hash);
        }

        llmq::chainLocksHandler->ProcessNewChainLock(-1, staleChainLock, hash);
        BOOST_REQUIRE(llmq::CChainLocksHandlerTestAccess::SetSeenTime(
            *llmq::chainLocksHandler, hash, static_cast<int64_t>(i)));
        BOOST_CHECK_LE(llmq::CChainLocksHandlerTestAccess::SeenCount(*llmq::chainLocksHandler), MAX_SEEN_CHAINLOCKS);
    }

    BOOST_CHECK_EQUAL(llmq::CChainLocksHandlerTestAccess::SeenCount(*llmq::chainLocksHandler), MAX_SEEN_CHAINLOCKS);
    BOOST_CHECK(!llmq::chainLocksHandler->AlreadyHave(CInv(MSG_CLSIG, firstStaleHash)));
    for (const uint256& hash : recentStaleHashes) {
        BOOST_CHECK(llmq::chainLocksHandler->AlreadyHave(CInv(MSG_CLSIG, hash)));
    }
    BOOST_CHECK(llmq::chainLocksHandler->AlreadyHave(CInv(MSG_CLSIG, bestHash)));
}

BOOST_AUTO_TEST_SUITE_END()
