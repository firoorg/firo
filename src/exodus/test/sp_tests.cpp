#include "../sp.h"

#include "test/test_bitcoin.h"
#include "main.h"
#include "miner.h"
#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

struct SpTestingSetup : public TestingSetup
{
    SpTestingSetup()
        : TestingSetup(CBaseChainParams::REGTEST), spinfo(pathTemp / "MP_spinfo_test", false)
    {
    }

    int GenerateEmptyBlock(size_t blocks)
    {
        int blockCount = 0;
        while (blocks--) {
            CReserveKey reserveKey(pwalletMain);
            auto blockTemplate = BlockAssembler(Params()).CreateNewBlockWithKey(reserveKey);
            auto block = blockTemplate->block;

            // IncrementExtraNonce creates a valid coinbase and merkleRoot
            unsigned int extraNonce = 0;
            IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

            while (!CheckProofOfWork(
                block.GetHash(), block.nBits, Params().GetConsensus())){
                ++block.nNonce;
            }

            delete blockTemplate;

            CValidationState state;
            if (ProcessNewBlock(state, Params(), nullptr, &block, true, nullptr, false)) {
                blockCount++;
            }
        }

        return blockCount;
    }

    CMPSPInfo spinfo;
};

BOOST_FIXTURE_TEST_SUITE(exodus_sp_tests, SpTestingSetup)

BOOST_AUTO_TEST_CASE(not_exist_sp)
{
    BOOST_CHECK_EXCEPTION(
        spinfo.getDenominationConfirmation(0, 0),
        std::invalid_argument,
        [](std::invalid_argument const &e) -> bool {
            return std::string("property notfound") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(not_exist_denomination)
{
    CMPSPInfo::Entry sp;
    spinfo.putSP(0, sp);
    BOOST_CHECK_EQUAL(
        0,
        spinfo.getDenominationConfirmation(0, 0)
    );
}

BOOST_AUTO_TEST_CASE(exist_denomination)
{
    GenerateEmptyBlock(10);
    CMPSPInfo::Entry sp;
    sp.creation_block = chainActive.Tip()->GetBlockHash();
    sp.update_block = sp.creation_block;
    auto property = spinfo.putSP(0, sp);

    // add new denom
    GenerateEmptyBlock(5);
    BOOST_CHECK(spinfo.getSP(property, sp));
    sp.update_block = chainActive.Tip()->GetBlockHash();
    sp.denominations = {1};
    BOOST_CHECK(spinfo.updateSP(property, sp));

    // 1 confirmation
    BOOST_CHECK_EQUAL(-1, spinfo.getDenominationConfirmation(property, 0, 0));
    BOOST_CHECK_EQUAL(1, spinfo.getDenominationConfirmation(property, 0));
    BOOST_CHECK_EQUAL(1, spinfo.getDenominationConfirmation(property, 0, 1));

    GenerateEmptyBlock(5);

    // 6 confimations
    BOOST_CHECK_EQUAL(-1, spinfo.getDenominationConfirmation(property, 0, 0));
    BOOST_CHECK_EQUAL(6, spinfo.getDenominationConfirmation(property, 0));
    BOOST_CHECK_EQUAL(6, spinfo.getDenominationConfirmation(property, 0, 6));

    // require 2 confirmations must return -1
    BOOST_CHECK_EQUAL(-1, spinfo.getDenominationConfirmation(property, 0, 2));
}

BOOST_AUTO_TEST_SUITE_END()