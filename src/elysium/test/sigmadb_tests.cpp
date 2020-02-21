#include "../createpayload.h"
#include "../sigmadb.h"
#include "../tx.h"

#include "../../test/fixtures.h"
#include "../../test/test_bitcoin.h"

#include <leveldb/db.h>

#include <boost/test/unit_test.hpp>

#include <forward_list>
#include <set>
#include <tuple>
#include <vector>

#define TEST_MAX_COINS_PER_GROUP 30

namespace std {

template<typename Char, typename Traits, typename Item1, typename Item2>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const pair<Item1, Item2>& p)
{
    return os << '(' << p.first << ", " << p.second << ')';
}

template<typename Char, typename Traits, typename Item, typename Allocator>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const vector<Item, Allocator>& v)
{
    os << '(';
    for (size_t i = 0; i < v.size();) {
        os << v[i];
        if (++i != v.size()) {
            os << ", ";
        }
    }
    os << ')';

    return os;
}

} // namespace std

namespace elysium {
namespace {

struct MintAdded
{
    PropertyId property;
    SigmaDenomination denomination;
    SigmaMintGroup group;
    SigmaMintIndex index;
    SigmaPublicKey pubKey;
    int block;
};

struct MintRemoved
{
    PropertyId property;
    SigmaDenomination denomination;
    SigmaPublicKey pubKey;
};

struct TestSigmaDb : SigmaDatabase
{
    TestSigmaDb(const boost::filesystem::path& path, bool wipe, uint16_t groupSize = TEST_MAX_COINS_PER_GROUP) :
        SigmaDatabase(path, wipe, groupSize)
    {
    }

    uint16_t GetGroupSize()
    {
        return SigmaDatabase::GetGroupSize();
    }

    uint16_t InitGroupSize(uint16_t groupSize)
    {
        return SigmaDatabase::InitGroupSize(groupSize);
    }

    std::vector<SigmaPublicKey> GetAnonimityGroupAsVector(
        PropertyId property,
        SigmaDenomination denomination,
        SigmaMintGroup group,
        size_t count)
    {
        std::vector<SigmaPublicKey> pubs;
        SigmaDatabase::GetAnonimityGroup(property, denomination, group, count, std::back_inserter(pubs));
        return pubs;
    }

    using SigmaDatabase::GetAnonimityGroup;
};

class SigmaDbTestingSetup : public TestingSetup
{
public:
    std::vector<MintAdded> mintAdded;
    std::vector<MintRemoved> mintRemoved;

public:
    SigmaDbTestingSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
    }

    std::unique_ptr<TestSigmaDb> CreateDb(uint16_t groupSize = TEST_MAX_COINS_PER_GROUP)
    {
        return CreateDb("MP_txlist_test", false, groupSize);
    }

    std::unique_ptr<TestSigmaDb> CreateDb(
        const std::string& fileName,
        bool wipe,
        uint16_t groupSize = TEST_MAX_COINS_PER_GROUP)
    {
        std::unique_ptr<TestSigmaDb> db(new TestSigmaDb(pathTemp / fileName, wipe, groupSize));

        sigconns.emplace_front(db->MintAdded.connect([this] (
            PropertyId p,
            SigmaDenomination d,
            SigmaMintGroup g,
            SigmaMintIndex i,
            const SigmaPublicKey& k,
            int b) {
            mintAdded.push_back(MintAdded{
                .property = p,
                .denomination = d,
                .group = g,
                .index = i,
                .pubKey = k,
                .block = b
            });
        }));

        sigconns.emplace_front(db->MintRemoved.connect([this] (
            PropertyId p,
            SigmaDenomination d,
            const SigmaPublicKey& k) {
            mintRemoved.push_back(MintRemoved{
                .property = p,
                .denomination = d,
                .pubKey = k
            });
        }));

        return db;
    }

private:
    std::forward_list<boost::signals2::scoped_connection> sigconns;
};

SigmaPublicKey CreateMint()
{
    SigmaPrivateKey key;
    key.Generate();
    return SigmaPublicKey(key, DefaultSigmaParams);
}

std::vector<SigmaPublicKey> CreateMints(size_t n)
{
    std::vector<SigmaPublicKey> mints;
    mints.reserve(n);

    while (n--) {
        mints.push_back(CreateMint());
    }

    return mints;
}

std::vector<SigmaPublicKey> GetFirstN(
    std::vector<SigmaPublicKey>& org, size_t n)
{
    return std::vector<SigmaPublicKey>
        (org.begin(), n > org.size() ? org.end() : org.begin() + n);
}

} // empty namespace

BOOST_FIXTURE_TEST_SUITE(exodus_sigmadb_tests, SigmaDbTestingSetup)

BOOST_AUTO_TEST_CASE(record_one_coin)
{
    auto db = CreateDb();
    auto mint = CreateMint();
    PropertyId propId = 1;
    SigmaDenomination denom = 0;

    BOOST_CHECK_EQUAL(0, db->GetMintCount(propId, denom, 0));
    BOOST_CHECK_EQUAL(0, db->GetNextSequence());

    BOOST_CHECK_EQUAL(
        std::make_pair(SigmaMintGroup(0), SigmaMintIndex(0)),
        db->RecordMint(propId, denom, mint, 100)
    );

    BOOST_CHECK_EQUAL(0, db->GetLastGroupId(propId, denom));
    BOOST_CHECK_EQUAL(1, db->GetMintCount(propId, denom, 0));
    BOOST_CHECK_EQUAL(0, db->GetMintCount(propId, denom, 1));
    BOOST_CHECK_EQUAL(1, db->GetNextSequence());

    BOOST_CHECK_EQUAL(1, mintAdded.size());
    BOOST_CHECK_EQUAL(propId, mintAdded[0].property);
    BOOST_CHECK_EQUAL(denom, mintAdded[0].denomination);
    BOOST_CHECK_EQUAL(0, mintAdded[0].group);
    BOOST_CHECK_EQUAL(0, mintAdded[0].index);
    BOOST_CHECK_EQUAL(mint, mintAdded[0].pubKey);
    BOOST_CHECK_EQUAL(100, mintAdded[0].block);
}

BOOST_AUTO_TEST_CASE(getmint_notfound)
{
    auto db = CreateDb();

    BOOST_CHECK_EXCEPTION(
        db->GetMint(1, 1, 1, 1),
        std::runtime_error,
        [] (const std::runtime_error &e) {
            return std::string("not found sigma mint") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(getmint_test)
{
    auto db = CreateDb();
    auto mint = CreateMint();
    uint32_t propId = 1;
    uint32_t denom = 0;
    db->RecordMint(propId, denom, mint, 100);

    BOOST_CHECK_EQUAL(mint, db->GetMint(propId, denom, 0, 0));
}

BOOST_AUTO_TEST_CASE(get_anonymityset_no_anycoin)
{
    auto db = CreateDb();

    BOOST_CHECK_EQUAL(db->GetAnonimityGroupAsVector(0, 0, 0, 100).empty(), true);
}

BOOST_AUTO_TEST_CASE(get_anonymityset_have_coin_in_other_group)
{
    auto db = CreateDb();

    for (auto& mint : CreateMints(10)) {
        db->RecordMint(1, 1, mint, 10);
    }

    BOOST_CHECK_EQUAL(db->GetAnonimityGroupAsVector(2, 2, 0, 11).empty(), true);
    BOOST_CHECK_EQUAL(db->GetAnonimityGroupAsVector(2, 2, 0, 1).empty(), true);
}

BOOST_AUTO_TEST_CASE(get_anonymityset_have_one_group)
{
    auto db = CreateDb();
    auto mints = CreateMints(10);

    for (auto& mint : mints) {
        db->RecordMint(1, 1, mint, 10);
    }

    BOOST_CHECK_EQUAL(mints, db->GetAnonimityGroupAsVector(1, 1, 0, 11));
    BOOST_CHECK_EQUAL(mints, db->GetAnonimityGroupAsVector(1, 1, 0, 10));
    BOOST_CHECK_EQUAL(GetFirstN(mints, 5), db->GetAnonimityGroupAsVector(1, 1, 0, 5));
}

BOOST_AUTO_TEST_CASE(get_anonymityset_many_properties)
{
    auto db = CreateDb();
    auto mints1 = CreateMints(10);
    auto mints2 = CreateMints(10);

    for (auto& mint : mints1) {
        db->RecordMint(1, 1, mint, 10);
    }

    for (auto& mint : mints2) {
        db->RecordMint(2, 1, mint, 10);
    }

    BOOST_CHECK_EQUAL(mints1, db->GetAnonimityGroupAsVector(1, 1, 0, 11));
    BOOST_CHECK_EQUAL(mints2, db->GetAnonimityGroupAsVector(2, 1, 0, 11));
    BOOST_CHECK_EQUAL(mints1, db->GetAnonimityGroupAsVector(1, 1, 0, 10));
    BOOST_CHECK_EQUAL(mints2, db->GetAnonimityGroupAsVector(2, 1, 0, 10));
    BOOST_CHECK_EQUAL(GetFirstN(mints1, 5), db->GetAnonimityGroupAsVector(1, 1, 0, 5));
    BOOST_CHECK_EQUAL(GetFirstN(mints2, 5), db->GetAnonimityGroupAsVector(2, 1, 0, 5));
}

BOOST_AUTO_TEST_CASE(get_anonymity_set_many_denominations)
{
    auto db = CreateDb();
    auto mints1 = CreateMints(10);
    auto mints2 = CreateMints(10);
    int blocks = 10;

    for (auto& mint : mints1) {
        db->RecordMint(1, 1, mint, blocks++);
    }

    for (auto& mint : mints2) {
        db->RecordMint(1, 2, mint, 10);
    }

    BOOST_CHECK_EQUAL(mints1, db->GetAnonimityGroupAsVector(1, 1, 0, 11));
    BOOST_CHECK_EQUAL(mints2, db->GetAnonimityGroupAsVector(1, 2, 0, 11));
    BOOST_CHECK_EQUAL(mints1, db->GetAnonimityGroupAsVector(1, 1, 0, 10));
    BOOST_CHECK_EQUAL(mints2, db->GetAnonimityGroupAsVector(1, 2, 0, 10));
    BOOST_CHECK_EQUAL(GetFirstN(mints1, 5), db->GetAnonimityGroupAsVector(1, 1, 0, 5));
    BOOST_CHECK_EQUAL(GetFirstN(mints2, 5), db->GetAnonimityGroupAsVector(1, 2, 0, 5));
}

BOOST_AUTO_TEST_CASE(get_anonymity_set_many_groups)
{
    auto db = CreateDb();
    auto mints1 = CreateMints(10);
    auto mints2 = CreateMints(10);
    int count = 0;

    for (auto& mint : mints1) {
        db->RecordMint(1, 1, mint, 10);
        count++;
    }

    for (; count < TEST_MAX_COINS_PER_GROUP; count++) {
        db->RecordMint(1, 1, mints1[0], 10);
    }

    for (auto& mint : mints2) {
        db->RecordMint(1, 1, mint, 10);
    }

    BOOST_CHECK_EQUAL(mints2, db->GetAnonimityGroupAsVector(1, 1, 1, 11));
    BOOST_CHECK_EQUAL(mints1, db->GetAnonimityGroupAsVector(1, 1, 0, 10));
    BOOST_CHECK_EQUAL(mints2, db->GetAnonimityGroupAsVector(1, 1, 1, 10));
    BOOST_CHECK_EQUAL(GetFirstN(mints1, 5), db->GetAnonimityGroupAsVector(1, 1, 0, 5));
    BOOST_CHECK_EQUAL(GetFirstN(mints2, 5), db->GetAnonimityGroupAsVector(1, 1, 1, 5));
}

BOOST_AUTO_TEST_CASE(delete_an_empty_set_of_coins)
{
    auto db = CreateDb();

    BOOST_CHECK_EQUAL(0, db->GetNextSequence());
    BOOST_CHECK_NO_THROW(db->DeleteAll(1));
    BOOST_CHECK_EQUAL(0, db->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_block_which_have_no_coins)
{
    auto db = CreateDb();
    auto mints = CreateMints(1);

    db->RecordMint(1, 1, mints[0], 10); // store at block 10

    BOOST_CHECK_NO_THROW(db->DeleteAll(11)); // delete at block 11
    BOOST_CHECK_EQUAL(mints, db->GetAnonimityGroupAsVector(1, 1, 0, 1));
    BOOST_CHECK_EQUAL(1, db->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_one_coin)
{
    auto db = CreateDb();
    auto mint = CreateMint();

    db->RecordMint(1, 1, mint, 10);

    BOOST_CHECK_NO_THROW(db->DeleteAll(10));

    BOOST_CHECK_EQUAL(0, db->GetAnonimityGroupAsVector(1, 1, 0, 1).size());
    BOOST_CHECK_EQUAL(0, db->GetNextSequence());

    BOOST_CHECK_EQUAL(1, mintRemoved.size());
    BOOST_CHECK_EQUAL(1, mintRemoved[0].property);
    BOOST_CHECK_EQUAL(1, mintRemoved[0].denomination);
    BOOST_CHECK_EQUAL(mint, mintRemoved[0].pubKey);
}

BOOST_AUTO_TEST_CASE(delete_one_of_two_coin)
{
    auto db = CreateDb();
    auto mints = CreateMints(2);

    db->RecordMint(1, 1, mints[0], 10); // store at block 10
    db->RecordMint(1, 1, mints[1], 11); // store at block 11

    BOOST_CHECK_NO_THROW(db->DeleteAll(11)); // delete at block 11

    BOOST_CHECK_EQUAL(GetFirstN(mints, 1), db->GetAnonimityGroupAsVector(1, 1, 0, 2));
    BOOST_CHECK_EQUAL(GetFirstN(mints, 1), db->GetAnonimityGroupAsVector(1, 1, 0, 1));
    BOOST_CHECK_EQUAL(1, db->GetNextSequence());

    BOOST_CHECK_EQUAL(1, mintRemoved.size());
    BOOST_CHECK_EQUAL(1, mintRemoved[0].property);
    BOOST_CHECK_EQUAL(1, mintRemoved[0].denomination);
    BOOST_CHECK_EQUAL(mints[1], mintRemoved[0].pubKey);
}

BOOST_AUTO_TEST_CASE(delete_two_coins_from_two_denominations)
{
    auto db = CreateDb();
    auto mints1 = CreateMints(2);
    auto mints2 = CreateMints(2);

    db->RecordMint(1, 0, mints1[0], 10);
    db->RecordMint(1, 1, mints2[0], 10);
    db->RecordMint(1, 0, mints1[1], 11);
    db->RecordMint(1, 1, mints2[1], 12);

    BOOST_CHECK_EQUAL(4, db->GetNextSequence());

    BOOST_CHECK_NO_THROW(db->DeleteAll(11));

    BOOST_CHECK_EQUAL(GetFirstN(mints1, 1), db->GetAnonimityGroupAsVector(1, 0, 0, 2));
    BOOST_CHECK_EQUAL(GetFirstN(mints2, 1), db->GetAnonimityGroupAsVector(1, 1, 0, 2));
    BOOST_CHECK_EQUAL(2, db->GetNextSequence());

    BOOST_CHECK_EQUAL(2, mintRemoved.size());
    BOOST_CHECK_EQUAL(1, mintRemoved[0].property);
    BOOST_CHECK_EQUAL(1, mintRemoved[0].denomination);
    BOOST_CHECK_EQUAL(mints2[1], mintRemoved[0].pubKey);

    BOOST_CHECK_EQUAL(1, mintRemoved[1].property);
    BOOST_CHECK_EQUAL(0, mintRemoved[1].denomination);
    BOOST_CHECK_EQUAL(mints1[1], mintRemoved[1].pubKey);
}

BOOST_AUTO_TEST_CASE(delete_two_coins_from_two_properties)
{
    auto db = CreateDb();
    auto mints1 = CreateMints(2);
    auto mints2 = CreateMints(2);

    db->RecordMint(1, 0, mints1[0], 10);
    db->RecordMint(2, 0, mints2[0], 10);
    db->RecordMint(1, 0, mints1[1], 11);
    db->RecordMint(2, 0, mints2[1], 12);

    BOOST_CHECK_EQUAL(4, db->GetNextSequence());

    BOOST_CHECK_NO_THROW(db->DeleteAll(11));

    BOOST_CHECK_EQUAL(GetFirstN(mints1, 1), db->GetAnonimityGroupAsVector(1, 0, 0, 2));
    BOOST_CHECK_EQUAL(GetFirstN(mints2, 1), db->GetAnonimityGroupAsVector(2, 0, 0, 2));
    BOOST_CHECK_EQUAL(2, db->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_three_coins_from_two_groups)
{
    auto db = CreateDb();
    auto mints1 = CreateMints(2);
    auto mints2 = CreateMints(2);
    unsigned count = 0;

    db->RecordMint(1, 0, mints1[0], 10);
    db->RecordMint(1, 0, mints1[1], 11);
    count += 2;

    for (;count < TEST_MAX_COINS_PER_GROUP; count++) {
        db->RecordMint(1, 0, mints1[0], 11);
    }

    BOOST_CHECK_EQUAL(std::make_pair(uint32_t(1), uint16_t(0)), db->RecordMint(1, 0, mints2[0], 12)); count++;
    BOOST_CHECK_EQUAL(std::make_pair(uint32_t(1), uint16_t(1)), db->RecordMint(1, 0, mints2[1], 13)); count++;
    BOOST_CHECK_EQUAL(1, db->GetLastGroupId(1, 0));
    BOOST_CHECK_EQUAL(count, db->GetNextSequence());

    BOOST_CHECK_NO_THROW(db->DeleteAll(11));

    BOOST_CHECK_EQUAL(GetFirstN(mints1, 1), db->GetAnonimityGroupAsVector(1, 0, 0, 2));
    BOOST_CHECK_EQUAL(db->GetAnonimityGroupAsVector(1, 0, 1, 1).empty(), true);
    BOOST_CHECK_EQUAL(1, db->GetNextSequence());
    BOOST_CHECK_EQUAL(0, db->GetLastGroupId(1, 0)); // assert last group id of propertyId = 1 and denomination = 0 is decreased to 0
}

BOOST_AUTO_TEST_CASE(get_anonimity_group_by_back_insert_iterator)
{
    auto db = CreateDb();
    auto mints = CreateMints(10);

    for (auto& mint : mints) {
        db->RecordMint(1, 1, mint, 10);
    }

    std::vector<SigmaPublicKey> anonimityGroup;
    db->GetAnonimityGroup(1, 1, 0, 10, std::back_inserter(anonimityGroup));

    BOOST_CHECK_EQUAL(mints, anonimityGroup);
}

BOOST_AUTO_TEST_CASE(get_anonimity_group_by_iterator)
{
    auto db = CreateDb();
    auto mints = CreateMints(10);
    std::vector<SigmaPublicKey> result(10);

    for (auto& mint : mints) {
        db->RecordMint(1, 1, mint, 10);
    }

    db->GetAnonimityGroup(1, 1, 0, 10, result.begin());

    BOOST_CHECK_EQUAL(mints, result);
}

BOOST_AUTO_TEST_CASE(group_size_default)
{
    auto db = CreateDb(0);

    BOOST_CHECK_EQUAL(db->GetGroupSize(), SigmaDatabase::MAX_GROUP_SIZE);
}

BOOST_AUTO_TEST_CASE(group_size_customsize)
{
    auto db = CreateDb(120);

    BOOST_CHECK_EQUAL(db->GetGroupSize(), 120);
}

BOOST_AUTO_TEST_CASE(group_size_exceed_limit)
{
    BOOST_CHECK_EXCEPTION(
        CreateDb(SigmaDatabase::MAX_GROUP_SIZE + 1),
        std::invalid_argument,
        [] (const std::invalid_argument& e) {
            return std::string("group size exceed limit") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(use_differnet_group_size_from_database)
{
    CreateDb(10);

    BOOST_CHECK_EXCEPTION(
        CreateDb(11),
        std::invalid_argument,
        [] (const std::invalid_argument& e) {
            return std::string("group size input isn't equal to group size in database")
                == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(check_not_exist_serial)
{
    auto db = CreateDb();
    SigmaPrivateKey key;

    key.Generate();
    uint256 spendTx;
    BOOST_CHECK(!db->HasSpendSerial(1, 1, key.serial, spendTx));
    BOOST_CHECK(uint256() == spendTx);
}

BOOST_AUTO_TEST_CASE(check_exist_serial)
{
    auto db = CreateDb();
    SigmaPrivateKey key;

    key.Generate();
    auto const spendTx = uint256S("1");
    db->RecordSpendSerial(1, 1, key.serial, 10, spendTx);

    uint256 outTx;
    BOOST_CHECK(db->HasSpendSerial(1, 1, key.serial, outTx));
    BOOST_CHECK(spendTx == outTx);
}

BOOST_AUTO_TEST_CASE(check_exist_serial_with_different_group_and_denom_should_fail)
{
    auto db = CreateDb();
    SigmaPrivateKey key;

    key.Generate();
    auto spendTx = uint256S("1");
    db->RecordSpendSerial(1, 1, key.serial, 10, spendTx);

    uint256 outputSpendTx;
    BOOST_CHECK_EQUAL(db->HasSpendSerial(1, 2, key.serial, outputSpendTx), false);
    BOOST_CHECK_EQUAL(db->HasSpendSerial(2, 1, key.serial, outputSpendTx), false);

    BOOST_CHECK(uint256() == outputSpendTx);
}

BOOST_AUTO_TEST_CASE(check_deleted_serial)
{
    auto db = CreateDb();
    SigmaPrivateKey key;

    key.Generate();

    auto spendTx = uint256S("1");
    db->RecordSpendSerial(1, 1, key.serial, 10, spendTx);
    db->DeleteAll(10);

    uint256 outputSpendTx;
    BOOST_CHECK_EQUAL(db->HasSpendSerial(1, 1, key.serial, outputSpendTx), false);

    BOOST_CHECK(uint256() == outputSpendTx);
}

BOOST_AUTO_TEST_CASE(check_deleted_two_serials)
{
    auto spendTx1 = uint256S("1");
    auto spendTx2 = uint256S("2");

    auto db = CreateDb();
    SigmaPrivateKey key1, key2;

    key1.Generate();
    key2.Generate();

    db->RecordSpendSerial(1, 1, key1.serial, 10, spendTx1);
    db->RecordSpendSerial(1, 1, key2.serial, 10, spendTx2);

    uint256 outputSpendTx1, outputSpendTx2;
    BOOST_CHECK(db->HasSpendSerial(1, 1, key1.serial, outputSpendTx1));
    BOOST_CHECK(db->HasSpendSerial(1, 1, key2.serial, outputSpendTx2));

    BOOST_CHECK(spendTx1 == outputSpendTx1);
    BOOST_CHECK(spendTx2 == outputSpendTx2);

    auto spendTx3 = uint256S("3");
    db->RecordSpendSerial(1, 1, key2.serial, 10, spendTx3);

    BOOST_CHECK_EQUAL(db->HasSpendSerial(1, 1, key1.serial, outputSpendTx1), true);
    BOOST_CHECK_EQUAL(db->HasSpendSerial(1, 1, key2.serial, outputSpendTx2), true);

    BOOST_CHECK(spendTx1 == outputSpendTx1);
    BOOST_CHECK(spendTx3 == outputSpendTx2);

    db->DeleteAll(10);

    uint256 spendTx4;
    BOOST_CHECK(!db->HasSpendSerial(1, 1, key1.serial, spendTx4));
    BOOST_CHECK(uint256() == spendTx4);

    BOOST_CHECK(!db->HasSpendSerial(1, 1, key2.serial, spendTx4));
    BOOST_CHECK(uint256() == spendTx4);
}

BOOST_AUTO_TEST_CASE(try_to_delete_the_block_after)
{
    auto spendTx1 = uint256S("1");
    auto spendTx2 = uint256S("2");

    auto db = CreateDb();
    SigmaPrivateKey key1, key2;

    key1.Generate();
    key2.Generate();
    db->RecordSpendSerial(1, 1, key1.serial, 10, spendTx1);
    db->RecordSpendSerial(1, 1, key2.serial, 11, spendTx2);

    db->DeleteAll(11);

    uint256 outputSpendTx1, outputSpendTx2;
    BOOST_CHECK(db->HasSpendSerial(1, 1, key1.serial, outputSpendTx1));
    BOOST_CHECK(!db->HasSpendSerial(1, 1, key2.serial, outputSpendTx2));

    BOOST_CHECK(spendTx1 == outputSpendTx1);
    BOOST_CHECK(uint256() == outputSpendTx2);
}

BOOST_AUTO_TEST_CASE(delete_both_mint_and_spend)
{
    auto spendTx1 = uint256S("1");
    auto spendTx2 = uint256S("2");

    auto db = CreateDb();
    SigmaPrivateKey key1, key2;

    key1.Generate();
    key2.Generate();

    // block 10
    // 10 mints, 1 serial
    for (auto& mint : CreateMints(10)) {
        db->RecordMint(1, 1, mint, 10);
    }

    db->RecordSpendSerial(1, 1, key1.serial, 10, spendTx1);
    BOOST_CHECK_EQUAL(11, db->GetNextSequence());
    BOOST_CHECK_EQUAL(10, db->GetMintCount(1, 1, 0));

    // block 11
    // 10 mints, 1 serial
    for (auto& mint : CreateMints(10)) {
        db->RecordMint(1, 1, mint, 11);
    }

    db->RecordSpendSerial(1, 1, key2.serial, 11, spendTx2);
    BOOST_CHECK_EQUAL(22, db->GetNextSequence());
    BOOST_CHECK_EQUAL(20, db->GetMintCount(1, 1, 0));

    // delete all in block 11
    db->DeleteAll(11);

    BOOST_CHECK_EQUAL(11, db->GetNextSequence());
    BOOST_CHECK_EQUAL(10, db->GetMintCount(1, 1, 0));

    uint256 outSpendTx1, outSpendTx2;
    BOOST_CHECK(db->HasSpendSerial(1, 1, key1.serial, outSpendTx1));
    BOOST_CHECK(!db->HasSpendSerial(1, 1, key2.serial, outSpendTx2));

    BOOST_CHECK(spendTx1 == outSpendTx1);
    BOOST_CHECK(uint256() == outSpendTx2);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
