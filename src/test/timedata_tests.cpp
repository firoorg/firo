// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include "timedata.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(timedata_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(util_MedianFilter)
{
    CMedianFilter<int> filter(5, 15);

    BOOST_CHECK_EQUAL(filter.median(), 15);

    filter.input(20); // [15 20]
    BOOST_CHECK_EQUAL(filter.median(), 17);

    filter.input(30); // [15 20 30]
    BOOST_CHECK_EQUAL(filter.median(), 20);

    filter.input(3); // [3 15 20 30]
    BOOST_CHECK_EQUAL(filter.median(), 17);

    filter.input(7); // [3 7 15 20 30]
    BOOST_CHECK_EQUAL(filter.median(), 15);

    filter.input(18); // [3 7 18 20 30]
    BOOST_CHECK_EQUAL(filter.median(), 18);

    filter.input(0); // [0 3 7 18 30]
    BOOST_CHECK_EQUAL(filter.median(), 7);
}

BOOST_AUTO_TEST_CASE(time_offset_range)
{
    const int64_t nMaxAdjustment = DEFAULT_MAX_TIME_ADJUSTMENT;
    const int64_t nSignedMax = std::numeric_limits<int64_t>::max();

    BOOST_CHECK(IsTimeOffsetWithinRange(0, nMaxAdjustment));
    BOOST_CHECK(IsTimeOffsetWithinRange(nMaxAdjustment, nMaxAdjustment));
    BOOST_CHECK(IsTimeOffsetWithinRange(-nMaxAdjustment, nMaxAdjustment));
    BOOST_CHECK(!IsTimeOffsetWithinRange(nMaxAdjustment + 1, nMaxAdjustment));
    BOOST_CHECK(!IsTimeOffsetWithinRange(-nMaxAdjustment - 1, nMaxAdjustment));
    BOOST_CHECK(!IsTimeOffsetWithinRange(std::numeric_limits<int64_t>::min(), nMaxAdjustment));
    BOOST_CHECK(!IsTimeOffsetWithinRange(nSignedMax, nMaxAdjustment));

    BOOST_CHECK(IsTimeOffsetWithinRange(nSignedMax, nSignedMax));
    BOOST_CHECK(IsTimeOffsetWithinRange(-nSignedMax, nSignedMax));
    BOOST_CHECK(!IsTimeOffsetWithinRange(std::numeric_limits<int64_t>::min(), nSignedMax));
    BOOST_CHECK(!IsTimeOffsetWithinRange(0, -1));
}

BOOST_AUTO_TEST_SUITE_END()
