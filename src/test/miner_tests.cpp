// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "miner.h"
#include "test/test_bitcoin.h"
#include "utiltime.h"
#include "validationinterface.h"

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <array>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>

BOOST_FIXTURE_TEST_SUITE(miner_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(extra_nonce_workers_are_independent)
{
    CBlockIndex previous;
    previous.nHeight = 1;
    const auto makeBlock = [](const char* previousHash) {
        CBlock block;
        block.hashPrevBlock = uint256S(previousHash);
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
        return block;
    };

    std::promise<void> firstReady, secondDone;
    auto first = std::async(std::launch::async, [&] {
        CBlock block = makeBlock("01");
        unsigned int extraNonce = 99;
        std::array<unsigned int, 3> nonces;
        IncrementExtraNonce(&block, &previous, extraNonce);
        nonces[0] = extraNonce;
        firstReady.set_value();
        secondDone.get_future().wait();
        IncrementExtraNonce(&block, &previous, extraNonce);
        nonces[1] = extraNonce;
        block.hashPrevBlock = uint256S("03");
        IncrementExtraNonce(&block, &previous, extraNonce);
        nonces[2] = extraNonce;
        return nonces;
    });
    auto second = std::async(std::launch::async, [&] {
        firstReady.get_future().wait();
        CBlock block = makeBlock("02");
        unsigned int extraNonce = 99;
        IncrementExtraNonce(&block, &previous, extraNonce);
        secondDone.set_value();
        return extraNonce;
    });

    const auto nonces = first.get();
    BOOST_CHECK_EQUAL(nonces[0], 1U);
    BOOST_CHECK_EQUAL(nonces[1], 2U);
    BOOST_CHECK_EQUAL(nonces[2], 1U);
    BOOST_CHECK_EQUAL(second.get(), 1U);
}

BOOST_AUTO_TEST_CASE(restart_and_stop_wait_for_workers)
{
    std::mutex mutex;
    std::condition_variable changed;
    unsigned int active = 0, started = 0, interrupted = 0;
    bool release = false;
    std::future<void> change;
    boost::signals2::scoped_connection connection(GetMainSignals().ScriptForMining.connect(
        [&](boost::shared_ptr<CReserveScript>& script) {
            std::unique_lock<std::mutex> lock(mutex);
            ++active;
            ++started;
            changed.notify_all();
            lock.unlock();
            try {
                while (true)
                    MilliSleep(1000);
            } catch (const boost::thread_interrupted&) {
                lock.lock();
                ++interrupted;
                changed.notify_all();
                changed.wait(lock, [&] { return release; });
                --active;
                changed.notify_all();
            }
            // An empty script makes the worker exit without touching chain or wallet state.
            script.reset();
        }));
    BOOST_SCOPE_EXIT_ALL(&) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            release = true;
            changed.notify_all();
        }
        GenerateBitcoins(false, 0, Params());
        std::unique_lock<std::mutex> lock(mutex);
        changed.wait(lock, [&] { return active == 0; });
    };

    GenerateBitcoins(true, 2, Params());
    {
        std::unique_lock<std::mutex> lock(mutex);
        BOOST_REQUIRE(changed.wait_for(lock, std::chrono::seconds(5), [&] { return started == 2; }));
    }
    change = std::async(std::launch::async, [] { GenerateBitcoins(true, 1, Params()); });
    {
        std::unique_lock<std::mutex> lock(mutex);
        BOOST_REQUIRE(changed.wait_for(lock, std::chrono::seconds(5), [&] { return interrupted == 2; }));
        BOOST_CHECK(change.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout);
        BOOST_CHECK_EQUAL(started, 2U);
        BOOST_CHECK_EQUAL(active, 2U);
        release = true;
        changed.notify_all();
    }
    change.get();
    {
        std::unique_lock<std::mutex> lock(mutex);
        BOOST_REQUIRE(changed.wait_for(lock, std::chrono::seconds(5), [&] { return started == 3; }));
        BOOST_CHECK_EQUAL(active, 1U);
        release = false;
    }
    change = std::async(std::launch::async, [] { GenerateBitcoins(false, 0, Params()); });
    {
        std::unique_lock<std::mutex> lock(mutex);
        BOOST_REQUIRE(changed.wait_for(lock, std::chrono::seconds(5), [&] { return interrupted == 3; }));
        BOOST_CHECK(change.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout);
        BOOST_CHECK_EQUAL(active, 1U);
        release = true;
        changed.notify_all();
    }
    change.get();
    std::lock_guard<std::mutex> lock(mutex);
    BOOST_CHECK_EQUAL(active, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
