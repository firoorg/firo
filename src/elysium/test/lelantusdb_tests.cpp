#include "../convert.h"
#include "../lelantusdb.h"

#include "../../test/fixtures.h"
#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

static const char DB_SERIAL_SEQUENCE    = 0x01;

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
        return GetNextSequence(DB_SERIAL_SEQUENCE);
    }

    bool WriteGroupSize(uint64_t groupSize, uint64_t mintAmount)
    {
        return LelantusDb::WriteGroupSize(groupSize, mintAmount);
    }

    std::pair<uint64_t, uint64_t> ReadGroupSize()
    {
        return LelantusDb::ReadGroupSize();
    }

    int GetLastGroup(PropertyId id, size_t &coins)
    {
        return LelantusDb::GetLastGroup(id, coins);
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

BOOST_AUTO_TEST_CASE(sliding_windows)
{
    auto db = CreateDb(1024, true, true, 100, 10);

    auto addCoins = [&](PropertyId id, size_t coins, int block) {
        for (size_t i = 0; i != coins; i++) {
            secp_primitives::GroupElement g;
            g.randomize();

            db->WriteMint(id, g, block);
        }
    };

    auto verifyLastGroup = [&](PropertyId id, int group, size_t coins) {
        size_t actualCoins;
        auto actualGroup = db->GetLastGroup(id, actualCoins);

        BOOST_CHECK_MESSAGE(actualGroup == group, strprintf("Expect group %d, actual %d", group, actualGroup));
        BOOST_CHECK_MESSAGE(actualCoins == coins, strprintf("Expect coins %d, actual %d", coins, actualCoins));
    };

    addCoins(1, 50, 10);
    verifyLastGroup(1, 0, 50);

    addCoins(1, 50, 11);
    verifyLastGroup(1, 0, 100);

    addCoins(1, 1, 12);
    verifyLastGroup(1, 1, 51);

    addCoins(1, 20, 13);
    verifyLastGroup(1, 1, 71);

    addCoins(1, 29, 13);
    verifyLastGroup(1, 1, 100);

    addCoins(1, 10, 14);
    verifyLastGroup(1, 2, 59);

    addCoins(1, 26, 15);
    verifyLastGroup(1, 2, 85);

    addCoins(1, 10, 16);
    verifyLastGroup(1, 2, 95);

    addCoins(1, 4, 17);
    verifyLastGroup(1, 2, 99);

    addCoins(1, 1, 17);
    verifyLastGroup(1, 2, 100);

    addCoins(1, 1, 17);
    verifyLastGroup(1, 3, 16);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium