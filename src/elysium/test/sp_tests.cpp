#include "../sp.h"

#include "../../test/test_bitcoin.h"
#include "../../main.h"
#include "../../miner.h"
#include "../../wallet/wallet.h"

#include <boost/test/unit_test.hpp>

struct SpTestingSetup : public TestChain100Setup
{
    SpTestingSetup()
        : db(pathTemp / "MP_spinfo_test", false)
    {
    }

    int GenerateEmptyBlock(size_t blocks)
    {
        int blockCount = 0;
        CReserveKey reserveKey(pwalletMain);
        while (blocks--) {
            CreateAndProcessBlock({}, reserveKey.reserveScript);
        }

        return blockCount;
    }

    CMPSPInfo db;
};

BOOST_FIXTURE_TEST_SUITE(elysium_sp_tests, SpTestingSetup)

BOOST_AUTO_TEST_CASE(not_exist_sp)
{
    BOOST_CHECK_EXCEPTION(
        db.getDenominationRemainingConfirmation(0, 0, 10),
        std::invalid_argument,
        [](std::invalid_argument const &e) -> bool {
            return std::string("property notfound") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(not_exist_denomination)
{
    CMPSPInfo::Entry sp;
    db.putSP(0, sp);
    BOOST_CHECK_EQUAL(
        100,
        db.getDenominationRemainingConfirmation(0, 0, 100)
    );
}

BOOST_AUTO_TEST_CASE(exist_denomination)
{
    CMPSPInfo::Entry sp;
    sp.creation_block = chainActive.Tip()->GetBlockHash();
    sp.update_block = sp.creation_block;
    auto property = db.putSP(0, sp);

    // add new denom
    GenerateEmptyBlock(5);
    BOOST_CHECK(db.getSP(property, sp));
    sp.update_block = chainActive.Tip()->GetBlockHash();
    sp.denominations = {1};
    BOOST_CHECK(db.updateSP(property, sp));

    // 1 confirmation
    BOOST_CHECK_EQUAL(0, db.getDenominationRemainingConfirmation(property, 0, 0));
    BOOST_CHECK_EQUAL(1, db.getDenominationRemainingConfirmation(property, 0, 2));
    BOOST_CHECK_EQUAL(0, db.getDenominationRemainingConfirmation(property, 0, 1));

    GenerateEmptyBlock(5);

    // 6 confimations
    BOOST_CHECK_EQUAL(0, db.getDenominationRemainingConfirmation(property, 0, 0));
    BOOST_CHECK_EQUAL(1, db.getDenominationRemainingConfirmation(property, 0, 7));
    BOOST_CHECK_EQUAL(0, db.getDenominationRemainingConfirmation(property, 0, 6));

    // require 2 confirmations must return 0
    BOOST_CHECK_EQUAL(0, db.getDenominationRemainingConfirmation(property, 0, 2));
}

BOOST_AUTO_TEST_SUITE_END()