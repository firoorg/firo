#include "../lelantusdb.h"

#include "../../test/fixtures.h"
#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace elysium {

namespace {

class TestLelantusDb : public LelantusDb
{
public:
    static const size_t DEFAULT_GROUPSIZE = 65000;
    static const size_t DEFAULT_STARTCOINS = 16000;

public:
    TestLelantusDb(
        size_t nCacheSize,
        bool fMemory = false,
        bool fWipe = false,
        size_t groupSize = DEFAULT_GROUPSIZE,
        size_t startCoins = DEFAULT_STARTCOINS)
        : LelantusDb(nCacheSize, fMemory, fWipe, groupSize, startCoins)
    {
    }

// proxy
public:
    uint64_t ReadNextSerialSequence()
    {
        return LelantusDb::ReadNextSerialSequence();
    }

    bool WriteGroupSize(uint64_t groupSize, uint64_t mintAmount)
    {
        return LelantusDb::WriteGroupSize(groupSize, mintAmount);
    }

    std::pair<uint64_t, uint64_t> ReadGroupSize()
    {
        return LelantusDb::ReadGroupSize();
    }
};

class LelantusDbTestingSetup : public TestingSetup
{
public:
    LelantusDbTestingSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
    }

    std::unique_ptr<TestLelantusDb> CreateDb(
        size_t nCacheSize,
        bool fMemory = false,
        bool fWipe = false,
        size_t groupSize = TestLelantusDb::DEFAULT_GROUPSIZE,
        size_t startCoins = TestLelantusDb::DEFAULT_STARTCOINS)
    {
        return std::unique_ptr<TestLelantusDb>(new TestLelantusDb(nCacheSize, fMemory, fWipe, groupSize, startCoins));
    }
};

} // empty namespace

BOOST_FIXTURE_TEST_SUITE(elysium_lelantusdb_tests, LelantusDbTestingSetup)

BOOST_AUTO_TEST_CASE(scalars)
{
    auto db = CreateDb(1024, true, true);

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

BOOST_AUTO_TEST_CASE(groupsize)
{
    auto db = CreateDb(1024, true, true, 1000, 200);

    BOOST_CHECK_MESSAGE(!db->WriteGroupSize(500, 100), "Success to overwrite group size");

    std::pair<uint64_t, uint64_t> expected(1000, 200);
    BOOST_CHECK(db->ReadGroupSize() == expected);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium