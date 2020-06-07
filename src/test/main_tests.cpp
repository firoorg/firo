// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "validation.h"
#include "net.h"

#include "test/test_bitcoin.h"

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    int maxHalvings = 64;
    CAmount nInitialSubsidy = 50 * COIN;

    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, consensusParams, consensusParams.nMTPSwitchTime-1000), nInitialSubsidy);
    nInitialSubsidy /= consensusParams.nMTPRewardReduction;
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2, consensusParams, consensusParams.nMTPSwitchTime), nInitialSubsidy);

    CAmount nPreviousSubsidy = nInitialSubsidy;
    for (int nHalvings = 1; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = consensusParams.nSubsidyHalvingFirst + (nHalvings-1) * consensusParams.nSubsidyHalvingInterval;
        if (nHeight >= consensusParams.nSubsidyHalvingStopBlock)
            break;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams, consensusParams.nMTPSwitchTime);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        if(nHeight > 0)
            BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nPreviousSubsidy / 2;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensusParams.nSubsidyHalvingStopBlock, consensusParams), 0);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    TestBlockSubsidyHalvings(Params(CBaseChainParams::MAIN).GetConsensus()); // As in main
    //TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    Consensus::Params consensusParams = Params(CBaseChainParams::MAIN).GetConsensus();
    CAmount nSum = 0;
    const int nMTPFirstBlock = 117564;
    int lastHalving = (consensusParams.nSubsidyHalvingStopBlock - consensusParams.nSubsidyHalvingFirst)/consensusParams.nSubsidyHalvingInterval;
    int lastHalvingBlock = consensusParams.nSubsidyHalvingFirst + lastHalving*consensusParams.nSubsidyHalvingInterval;

    int step = 1;

    for(int nHeight = 0; nHeight < 14000000; nHeight += step)
    {
        if (nHeight == consensusParams.nSubsidyHalvingFirst)
            step = 1000;
        else if (nHeight == lastHalvingBlock)
            step = 1;
        else if (nHeight == consensusParams.nSubsidyHalvingStopBlock)
            step = 10000;

        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams, nHeight<nMTPFirstBlock ? consensusParams.nMTPSwitchTime-1000 : consensusParams.nMTPSwitchTime);
        if (nHeight == 0)
            nSubsidy = 50*COIN;
        BOOST_CHECK(nSubsidy <= 50 * COIN);
        nSum += nSubsidy * step;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, 2095751201171875ULL);
}

bool ReturnFalse() { return false; }
bool ReturnTrue() { return true; }

BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool (), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}
BOOST_AUTO_TEST_SUITE_END()
