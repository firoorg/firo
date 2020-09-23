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

    uint256 spendTx;

#define HAS(id, s) BOOST_CHECK_MESSAGE(db->HasSerial(id, s, spendTx), \
    strprintf("Expect to have %s in group %d, but not found", secp_primitives::Scalar(s).GetHex(), id))

#define HAS_NO(id, s) BOOST_CHECK_MESSAGE(!db->HasSerial(id, s, spendTx), \
    strprintf("Expect to have no %s in group %d, but found", secp_primitives::Scalar(s).GetHex(), id))

    // have no serials before adding
    HAS_NO(2, 1);
    HAS_NO(3, 2);
    HAS_NO(3, 3);

    BOOST_CHECK_EQUAL(0, db->ReadNextSerialSequence());

    uint256 dummyTx = ArithToUint256(arith_uint256(100));

    // add some serials
    BOOST_CHECK(db->WriteSerial(2, 1, 10, dummyTx));
    BOOST_CHECK(db->WriteSerial(3, 2, 10, dummyTx));
    BOOST_CHECK(db->WriteSerial(3, 3, 10, dummyTx));

    BOOST_CHECK_EQUAL(3, db->ReadNextSerialSequence());

    // confirm serials are added
    HAS(2, 1);
    HAS(3, 2);
    HAS(3, 3);

    // confirm serials are not included
    HAS_NO(2, 2);
    HAS_NO(2, 3);
    HAS_NO(2, 4);

    // test spend tx
    uint256 tx1 = ArithToUint256(arith_uint256(101));
    uint256 tx2 = ArithToUint256(arith_uint256(102));

    // add some serials with unique spend txs
    BOOST_CHECK(db->WriteSerial(2, 3, 11, tx1));
    BOOST_CHECK(db->WriteSerial(2, 4, 11, tx2));

    BOOST_CHECK_EQUAL(5, db->ReadNextSerialSequence());

    // verify serials are added
    HAS(2, 3);
    HAS(2, 4);

    // verify spend tx are recorded correctly
    uint256 recordedTx;
    BOOST_CHECK(db->HasSerial(2, 3, recordedTx));
    BOOST_CHECK_MESSAGE(tx1 == recordedTx,
        strprintf("Expected spendTx %s, got %s", tx1.GetHex(), recordedTx.GetHex()));

    BOOST_CHECK(db->HasSerial(2, 4, recordedTx));
    BOOST_CHECK_MESSAGE(tx2 == recordedTx,
        strprintf("Expected spendTx %s, got %s", tx2.GetHex(), recordedTx.GetHex()));

    // try to add duplicated serial, should fail
    BOOST_CHECK_MESSAGE(!db->WriteSerial(2, 3, 12, tx1), "Success to write duplicated serial");

    // add one more should success
    BOOST_CHECK_MESSAGE(db->WriteSerial(4, 99, 12, tx1), "Fail to write serial");

    HAS(4, 99);

    // remove by block number
    db->RemoveSerials(12);

    HAS_NO(4, 99);

    // verify serials in block before 12 are included
    HAS(2, 1);
    HAS(3, 2);
    HAS(3, 3);

    HAS(2, 3);
    HAS(2, 4);

    // remove to all
    db->RemoveSerials(0);

    HAS_NO(2, 3);
    HAS_NO(2, 4);

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