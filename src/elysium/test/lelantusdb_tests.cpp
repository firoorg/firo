#include "../lelantusdb.h"

#include "../../test/fixtures.h"
#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace elysium {

namespace {

class TestLelantusDb : public LelantusDb
{
public:
    TestLelantusDb() : LelantusDb(100)
    {
    }

// proxy
public:
    uint64_t ReadNextSerialSequence()
    {
        return LelantusDb::ReadNextSerialSequence();
    }
};

class LelantusDbTestingSetup : public TestingSetup
{
public:
    LelantusDbTestingSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
    }

    std::unique_ptr<TestLelantusDb> CreateDb()
    {
        return std::unique_ptr<TestLelantusDb>(new TestLelantusDb());
    }
};

} // empty namespace

BOOST_FIXTURE_TEST_SUITE(elysium_lelantusdb_tests, LelantusDbTestingSetup)

BOOST_AUTO_TEST_CASE(scalars)
{
    auto db = CreateDb();

#define HAS(id, s) BOOST_CHECK_MESSAGE(db->HasSerial(id, s), \
    strprintf("Expect to have %s in group %d, but not found", secp_primitives::Scalar(s).GetHex(), id))

#define HAS_NO(id, s) BOOST_CHECK_MESSAGE(!db->HasSerial(id, s), \
    strprintf("Expect to have no %s in group %d, but found", secp_primitives::Scalar(s).GetHex(), id))

    HAS_NO(2, 1);
    HAS_NO(3, 2);
    HAS_NO(3, 3);

    BOOST_CHECK_EQUAL(0, db->ReadNextSerialSequence());

    db->WriteSerials(10, {
        {2, {1}},
        {3, {2, 3}}
    });

    BOOST_CHECK_EQUAL(3, db->ReadNextSerialSequence());

    HAS(2, 1);
    HAS(3, 2);

    HAS_NO(2, 2);

    HAS_NO(2, 3);
    HAS_NO(2, 4);

    db->WriteSerials(11, {
        {2, {3, 4}},
    });

    BOOST_CHECK_EQUAL(5, db->ReadNextSerialSequence());

    HAS(2, 3);
    HAS(2, 4);

    db->RemoveSerials(11);

    BOOST_CHECK_EQUAL(3, db->ReadNextSerialSequence());

    HAS_NO(2, 3);
    HAS_NO(2, 4);

    db->RemoveSerials(0);

    HAS_NO(2, 1);
    HAS_NO(3, 2);
    HAS_NO(3, 3);

    BOOST_CHECK_EQUAL(0, db->ReadNextSerialSequence());

#undef HAS
#undef HAS_NO
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium