// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "validation.h"
#include "net.h"

#include "test/test_bitcoin.h"

#include <boost/scope_exit.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

namespace {
struct TransactionLookupSetup : TestChain100Setup {
    TransactionLookupSetup() : TestChain100Setup(0) {}
};
}

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(gettransaction_txindex_miss)
{
    LOCK(cs_main);
    struct CountingCoinsView : CCoinsView {
        mutable size_t reads = 0;
        bool GetCoin(const COutPoint&, Coin&) const override
        {
            ++reads;
            return false;
        }
    } view;
    CCoinsViewCache coins(&view);
    CCoinsViewCache* const savedCoinsTip = pcoinsTip;
    const bool savedTxIndex = fTxIndex;
    BOOST_SCOPE_EXIT_ALL(&) {
        pcoinsTip = savedCoinsTip;
        fTxIndex = savedTxIndex;
    };
    pcoinsTip = &coins;

    const uint256 missing = uint256S("01");
    CTransactionRef tx;
    uint256 hashBlock;
    for (bool indexed : {true, false}) {
        fTxIndex = indexed;
        view.reads = 0;
        BOOST_CHECK(!GetTransaction(missing, tx, Params().GetConsensus(), hashBlock, false));
        BOOST_CHECK_EQUAL(view.reads, 0U);
        BOOST_CHECK(!GetTransaction(missing, tx, Params().GetConsensus(), hashBlock, true));
        if (indexed) {
            BOOST_CHECK_EQUAL(view.reads, 0U);
        } else {
            BOOST_CHECK_GT(view.reads, 0U);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(gettransaction_lookup_paths, TransactionLookupSetup)
{
    LOCK(cs_main);
    const bool savedTxIndex = fTxIndex;
    BOOST_SCOPE_EXIT_ALL(&) { fTxIndex = savedTxIndex; };
    fTxIndex = true;
    const CBlock block = CreateAndProcessBlock({}, coinbaseKey);
    const uint256 confirmed = block.vtx[0]->GetHash();
    CTransactionRef tx;
    uint256 hashBlock;

    // Indexed lookup does not need the UTXO fallback.
    BOOST_REQUIRE(GetTransaction(confirmed, tx, Params().GetConsensus(), hashBlock, false));
    BOOST_CHECK(tx->GetHash() == confirmed);
    BOOST_CHECK(hashBlock == block.GetHash());

    // Without an index, confirmed transactions with unspent outputs remain retrievable.
    fTxIndex = false;
    BOOST_CHECK(!GetTransaction(confirmed, tx, Params().GetConsensus(), hashBlock, false));
    BOOST_REQUIRE(GetTransaction(confirmed, tx, Params().GetConsensus(), hashBlock, true));
    BOOST_CHECK(tx->GetHash() == confirmed);
    BOOST_CHECK(hashBlock == block.GetHash());

    CMutableTransaction pending;
    pending.vin.emplace_back(COutPoint(confirmed, 0));
    pending.vout.emplace_back(COIN, CScript() << OP_TRUE);
    for (CTxMemPool* pool : {&mempool, &txpools.getStemTxPool()}) {
        ++pending.nLockTime;
        pool->addUnchecked(pending.GetHash(), TestMemPoolEntryHelper().FromTx(pending));
        for (bool indexed : {false, true}) {
            fTxIndex = indexed;
            for (bool allowSlow : {false, true}) {
                BOOST_REQUIRE(GetTransaction(pending.GetHash(), tx, Params().GetConsensus(), hashBlock, allowSlow));
                BOOST_CHECK(tx->GetHash() == pending.GetHash());
            }
        }
    }
}

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    FIRO_UNUSED int maxHalvings = 64;
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
