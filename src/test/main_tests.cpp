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
    __firo_unused int maxHalvings = 64;
    CAmount nInitialSubsidy = 50 * COIN;

    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, consensusParams, consensusParams.nMTPSwitchTime-1000), nInitialSubsidy);
    nInitialSubsidy /= consensusParams.nMTPRewardReduction;
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2, consensusParams, consensusParams.nMTPSwitchTime), nInitialSubsidy);
    CAmount baseSubsidy = nInitialSubsidy;

    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensusParams.nSubsidyHalvingFirst, consensusParams, consensusParams.nMTPSwitchTime), baseSubsidy/2);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensusParams.stage3StartBlock, consensusParams, consensusParams.stage3StartTime), baseSubsidy/4);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensusParams.nSubsidyHalvingSecond, consensusParams, consensusParams.stage3StartTime), baseSubsidy/4);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensusParams.nSubsidyHalvingSecond + consensusParams.nSubsidyHalvingInterval,
                consensusParams, consensusParams.stage3StartTime), consensusParams.tailEmissionBlockSubsidy/consensusParams.nMTPRewardReduction/2);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    TestBlockSubsidyHalvings(Params(CBaseChainParams::MAIN).GetConsensus()); // As in main
    //TestBlockSubsidyHalvings(1000); // Just another interval
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
