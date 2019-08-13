#include <tuple>

#include "exodus/sigmadb.h"
#include "exodus/tx.h"
#include "exodus/createpayload.h"

#include <boost/test/unit_test.hpp>

#include <set>

#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "leveldb/db.h"

#define TEST_MAX_COINS_PER_GROUP 30

#define GROUPSIZE_KEY_SIZE 1

// proxy
class CMPMintList : public exodus::CMPMintList
{
public:
    CMPMintList(const boost::filesystem::path& path, bool fWipe, uint16_t groupSize = 0)
        : exodus::CMPMintList(path, fWipe, groupSize)
    {
    }

    uint16_t GetGroupSize()
    {
        return exodus::CMPMintList::GetGroupSize();
    }

    uint16_t InitGroupSize(uint16_t groupSize)
    {
        return exodus::CMPMintList::InitGroupSize(groupSize);
    }
};

struct DBTestSetup : TestingSetup
{
    DBTestSetup()
        : TestingSetup(CBaseChainParams::REGTEST),
        db(pathTemp / "MP_txlist_test", false, TEST_MAX_COINS_PER_GROUP)
    {
    }
    ~DBTestSetup()
    {
        db.Clear();
    }

    std::unique_ptr<CMPMintList> CreateCMPMintList(const std::string& fileName, uint16_t groupSize)
    {
        return std::unique_ptr<CMPMintList>(new CMPMintList(pathTemp / fileName, false, groupSize));
    }

    exodus::CMPMintList db;

    std::vector<exodus::SigmaPublicKey> GetAnonimityGroup(
        uint32_t propertyId, uint32_t denomination, uint32_t groupId, size_t count)
    {
        std::vector<exodus::SigmaPublicKey> pubs;
        db.GetAnonimityGroup(
            propertyId, denomination, groupId, count, std::back_inserter(pubs));
        return pubs;
    }
};

BOOST_FIXTURE_TEST_SUITE(exodus_sigmadb_tests, DBTestSetup)

static exodus::SigmaPublicKey GetNewPubcoin()
{
    exodus::SigmaPrivateKey priv;
    priv.Generate();
    return exodus::SigmaPublicKey(priv);
}

static std::vector<exodus::SigmaPublicKey> GetPubcoins(size_t n)
{
    std::vector<exodus::SigmaPublicKey> pubs;
    while (n--) {
        pubs.push_back(GetNewPubcoin());
    }
    return pubs;
}

static std::vector<exodus::SigmaPublicKey> GetFirstN(
    std::vector<exodus::SigmaPublicKey>& org, size_t n)
{
    return std::vector<exodus::SigmaPublicKey>
        (org.begin(), n > org.size() ? org.end() : org.begin() + n);
}

BOOST_AUTO_TEST_CASE(record_one_coin)
{
    auto mint = GetNewPubcoin();
    uint32_t propId = 1;
    uint32_t denom = 0;

    BOOST_CHECK_EQUAL(0,
        db.GetMintCount(propId, denom, 0));
    BOOST_CHECK_EQUAL(0,
        db.GetNextSequence());

    BOOST_CHECK(std::make_pair(uint32_t(0), uint16_t(0)) ==
        db.RecordMint(propId, denom, mint, 100));

    BOOST_CHECK_EQUAL(0,
        db.GetLastGroupId(propId, denom));
    BOOST_CHECK_EQUAL(1,
        db.GetMintCount(propId, denom, 0));
    BOOST_CHECK_EQUAL(0,
        db.GetMintCount(propId, denom, 1));
    BOOST_CHECK_EQUAL(1,
        db.GetNextSequence());
}

BOOST_AUTO_TEST_CASE(getmint_notfound)
{
    BOOST_CHECK_EXCEPTION(
        db.GetMint(1, 1, 1, 1),
        std::runtime_error,
        [] (const std::runtime_error &e) {
            return std::string("not found sigma mint") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(getmint_test)
{
    auto mint = GetNewPubcoin();
    uint32_t propId = 1;
    uint32_t denom = 0;
    db.RecordMint(propId, denom, mint, 100);

    BOOST_CHECK(
        std::make_pair(mint, int(100)) ==
        db.GetMint(propId, denom, 0, 0)
    );
}

BOOST_AUTO_TEST_CASE(get_anonymityset_no_anycoin)
{
    BOOST_CHECK(GetAnonimityGroup(0, 0, 0, 100).empty());
}

BOOST_AUTO_TEST_CASE(get_anonymityset_have_coin_in_other_group)
{
    auto pubs = GetPubcoins(10);
    for (auto const &pub : pubs) {
        db.RecordMint(1, 1, pub, 10);
    }
    BOOST_CHECK(GetAnonimityGroup(2, 2, 0, 11).empty());
    BOOST_CHECK(GetAnonimityGroup(2, 2, 0, 1).empty());
}

BOOST_AUTO_TEST_CASE(get_anonymityset_have_one_group)
{
    auto pubs = GetPubcoins(10);
    for (auto const &pub : pubs) {
        db.RecordMint(1, 1, pub, 10);
    }

    BOOST_CHECK(pubs == GetAnonimityGroup(1, 1, 0, 11));
    BOOST_CHECK(pubs == GetAnonimityGroup(1, 1, 0, 10));
    BOOST_CHECK(GetFirstN(pubs, 5) == GetAnonimityGroup(1, 1, 0, 5));
}

BOOST_AUTO_TEST_CASE(get_anonymityset_many_properties)
{
    auto pubs = GetPubcoins(10);
    for (auto const &pub : pubs) {
        db.RecordMint(1, 1, pub, 10);
    }

    auto property2Pubs = GetPubcoins(10);
    for (auto const &pub : property2Pubs) {
        db.RecordMint(2, 1, pub, 10);
    }

    BOOST_CHECK(pubs == GetAnonimityGroup(1, 1, 0, 11));
    BOOST_CHECK(property2Pubs == GetAnonimityGroup(2, 1, 0, 11));
    BOOST_CHECK(pubs == GetAnonimityGroup(1, 1, 0, 10));
    BOOST_CHECK(property2Pubs == GetAnonimityGroup(2, 1, 0, 10));
    BOOST_CHECK(GetFirstN(pubs, 5) == GetAnonimityGroup(1, 1, 0, 5));
    BOOST_CHECK(GetFirstN(property2Pubs, 5) == GetAnonimityGroup(2, 1, 0, 5));
}

BOOST_AUTO_TEST_CASE(get_anonymity_set_many_denominations)
{
    auto pubs = GetPubcoins(10);
    auto denom2Pubs = GetPubcoins(10);

    int blocks = 10;
    for (size_t i = 0; i < pubs.size(); i++) {
        db.RecordMint(1, 1, pubs[i], blocks);
        db.RecordMint(1, 2, denom2Pubs[i], 10);
        blocks++;
    }

    BOOST_CHECK(pubs == GetAnonimityGroup(1, 1, 0, 11));
    BOOST_CHECK(denom2Pubs == GetAnonimityGroup(1, 2, 0, 11));
    BOOST_CHECK(pubs == GetAnonimityGroup(1, 1, 0, 10));
    BOOST_CHECK(denom2Pubs == GetAnonimityGroup(1, 2, 0, 10));
    BOOST_CHECK(GetFirstN(pubs, 5) == GetAnonimityGroup(1, 1, 0, 5));
    BOOST_CHECK(GetFirstN(denom2Pubs, 5) == GetAnonimityGroup(1, 2, 0, 5));
}

BOOST_AUTO_TEST_CASE(get_anonymity_set_many_groups)
{
    auto pubs = GetPubcoins(10);
    int countGroup1 = 0;
    for (auto const &pub : pubs) {
        db.RecordMint(1, 1, pub, 10);
        countGroup1++;
    }

    for (; countGroup1 < TEST_MAX_COINS_PER_GROUP; countGroup1++) {
        db.RecordMint(1, 1, pubs[0], 10);
    }

    auto group1Pubs = GetPubcoins(10);
    for (auto const &pub : group1Pubs) {
        db.RecordMint(1, 1, pub, 10);
    }

    BOOST_CHECK(group1Pubs == GetAnonimityGroup(1, 1, 1, 11));
    BOOST_CHECK(pubs == GetAnonimityGroup(1, 1, 0, 10));
    BOOST_CHECK(group1Pubs == GetAnonimityGroup(1, 1, 1, 10));
    BOOST_CHECK(GetFirstN(pubs, 5) == GetAnonimityGroup(1, 1, 0, 5));
    BOOST_CHECK(GetFirstN(group1Pubs, 5) == GetAnonimityGroup(1, 1, 1, 5));
}

BOOST_AUTO_TEST_CASE(delete_an_empty_set_of_coins)
{
    BOOST_CHECK_EQUAL(0, db.GetNextSequence());
    BOOST_CHECK_NO_THROW(db.DeleteAll(1));
    BOOST_CHECK_EQUAL(0, db.GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_block_which_have_no_coins)
{
    auto pubs = GetPubcoins(1);
    db.RecordMint(1, 1, pubs[0], 10); // store at block 10
    BOOST_CHECK_NO_THROW(db.DeleteAll(11)); // delete at block 11
    BOOST_CHECK(pubs == GetAnonimityGroup(1, 1, 0, 1));
    BOOST_CHECK_EQUAL(1, db.GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_one_coin)
{
    auto pubs = GetPubcoins(1);
    db.RecordMint(1, 1, pubs[0], 10);
    BOOST_CHECK_NO_THROW(db.DeleteAll(10));
    BOOST_CHECK_EQUAL(0, GetAnonimityGroup(1, 1, 0, 1).size());
    BOOST_CHECK_EQUAL(0, db.GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_one_of_two_coin)
{
    auto pubs = GetPubcoins(2);
    db.RecordMint(1, 1, pubs[0], 10); // store at block 10
    db.RecordMint(1, 1, pubs[1], 11); // store at block 11
    BOOST_CHECK_NO_THROW(db.DeleteAll(11)); // delete at block 11
    BOOST_CHECK(GetFirstN(pubs, 1) == GetAnonimityGroup(1, 1, 0, 2));
    BOOST_CHECK(GetFirstN(pubs, 1) == GetAnonimityGroup(1, 1, 0, 1));
    BOOST_CHECK_EQUAL(1, db.GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_two_coins_from_two_denominations)
{
    auto pubs = GetPubcoins(2);
    auto denom2Pubs = GetPubcoins(2);

    // RecordMint(propertyId, denomination, mint, block)
    db.RecordMint(1, 0, pubs[0], 10);
    db.RecordMint(1, 1, denom2Pubs[0], 10);
    db.RecordMint(1, 0, pubs[1], 11);
    db.RecordMint(1, 1, denom2Pubs[1], 12);

    BOOST_CHECK_EQUAL(4, db.GetNextSequence());

    BOOST_CHECK_NO_THROW(db.DeleteAll(11));

    BOOST_CHECK(GetFirstN(pubs, 1) == GetAnonimityGroup(1, 0, 0, 2));
    BOOST_CHECK(GetFirstN(denom2Pubs, 1) == GetAnonimityGroup(1, 1, 0, 2));
    BOOST_CHECK_EQUAL(2, db.GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_two_coins_from_two_properties)
{
    auto pubs = GetPubcoins(2);
    auto property2Pubs = GetPubcoins(2);

    // RecordMint(propertyId, denomination, mint, block)
    db.RecordMint(1, 0, pubs[0], 10);
    db.RecordMint(2, 0, property2Pubs[0], 10);
    db.RecordMint(1, 0, pubs[1], 11);
    db.RecordMint(2, 0, property2Pubs[1], 12);

    BOOST_CHECK_EQUAL(4, db.GetNextSequence());

    BOOST_CHECK_NO_THROW(db.DeleteAll(11));

    BOOST_CHECK(GetFirstN(pubs, 1) == GetAnonimityGroup(1, 0, 0, 2));
    BOOST_CHECK(GetFirstN(property2Pubs, 1) == GetAnonimityGroup(2, 0, 0, 2));
    BOOST_CHECK_EQUAL(2, db.GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_three_coins_from_two_groups)
{
    auto pubs = GetPubcoins(2);
    auto group1Pubs = GetPubcoins(2);
    db.RecordMint(1, 0, pubs[0], 10);
    db.RecordMint(1, 0, pubs[1], 11);

    size_t coinCount = 2;
    for (;coinCount < TEST_MAX_COINS_PER_GROUP; coinCount++) {
        db.RecordMint(1, 0, pubs[0], 11);
    }

    BOOST_CHECK(std::make_pair(uint32_t(1), uint16_t(0)) ==
        db.RecordMint(1, 0, group1Pubs[0], 12));
    BOOST_CHECK(std::make_pair(uint32_t(1), uint16_t(1)) ==
        db.RecordMint(1, 0, group1Pubs[1], 13));

    BOOST_CHECK_EQUAL(1, db.GetLastGroupId(1, 0));

    BOOST_CHECK_EQUAL(coinCount + 2, db.GetNextSequence());

    BOOST_CHECK_NO_THROW(db.DeleteAll(11));

    BOOST_CHECK(GetFirstN(pubs, 1) == GetAnonimityGroup(1, 0, 0, 2));

    BOOST_CHECK(GetAnonimityGroup(1, 0, 1, 1).empty());

    BOOST_CHECK_EQUAL(1, db.GetNextSequence());

    // assert last group id of propertyId = 1 and denomination = 0 is decreased to 0
    BOOST_CHECK_EQUAL(0, db.GetLastGroupId(1, 0));
}

BOOST_AUTO_TEST_CASE(get_anonimity_group_by_back_insert_iterator)
{
    size_t cointAmount = 10;
    auto pubs = GetPubcoins(cointAmount);
    for (auto const &pub : pubs) {
        db.RecordMint(1, 1, pub, 10);
    }

    std::vector<exodus::SigmaPublicKey> anonimityGroup;
    db.GetAnonimityGroup(1, 1, 0, cointAmount, std::back_inserter(anonimityGroup));

    BOOST_CHECK(pubs == anonimityGroup);
}

BOOST_AUTO_TEST_CASE(get_anonimity_group_by_iterator)
{
    constexpr size_t coinAmount = 10;
    auto pubs = GetPubcoins(coinAmount);
    for (auto const &pub : pubs) {
        db.RecordMint(1, 1, pub, 10);
    }

    std::vector<exodus::SigmaPublicKey> anonimityGroup;
    anonimityGroup.resize(coinAmount);
    db.GetAnonimityGroup(1, 1, 0, coinAmount, anonimityGroup.begin());

    BOOST_CHECK(pubs == anonimityGroup);

    std::array<exodus::SigmaPublicKey, coinAmount> anonimityGroupArr;
    db.GetAnonimityGroup(1, 1, 0, coinAmount, anonimityGroupArr.begin());
    BOOST_CHECK(pubs == std::vector<exodus::SigmaPublicKey>(anonimityGroupArr.begin(), anonimityGroupArr.end()));

    std::list<exodus::SigmaPublicKey> anonimityGroupList;
    anonimityGroupList.resize(coinAmount);
    db.GetAnonimityGroup(1, 1, 0, coinAmount, anonimityGroupList.begin());
    BOOST_CHECK(pubs == std::vector<exodus::SigmaPublicKey>(anonimityGroupList.begin(), anonimityGroupList.end()));
}

BOOST_AUTO_TEST_CASE(group_size_default)
{
    std::string testingDefaultFile = "MP_txlist_groupsize_test";

    auto CMPMintListProxy = CreateCMPMintList(testingDefaultFile, 0);
    uint16_t defaultGroupSize = exodus::CMPMintList::MAX_GROUP_SIZE;
    BOOST_CHECK_EQUAL(CMPMintListProxy->GetGroupSize(), defaultGroupSize);
}

BOOST_AUTO_TEST_CASE(group_size_customsize)
{
    std::string testingDefaultFile = "MP_txlist_groupsize_test";

    auto CMPMintListProxy = CreateCMPMintList(testingDefaultFile, 120);
    BOOST_CHECK_EQUAL(CMPMintListProxy->GetGroupSize(), 120);
}

BOOST_AUTO_TEST_CASE(group_size_exceed_limit)
{
    std::string testingDefaultFile = "MP_txlist_groupsize_test";

    uint16_t defaultGroupSize = exodus::CMPMintList::MAX_GROUP_SIZE;

    std::unique_ptr<CMPMintList> CMPMintListProxy;
    BOOST_CHECK_EXCEPTION(
        CMPMintListProxy = CreateCMPMintList(testingDefaultFile, defaultGroupSize + 1),
        std::invalid_argument,
        [] (const std::invalid_argument& e) {
            return std::string("group size exceed limit") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(use_differnet_group_size_from_database)
{
    std::string testingDefaultFile = "MP_txlist_groupsize_test";

    std::unique_ptr<CMPMintList> CMPMintListProxy;
    CMPMintListProxy = CreateCMPMintList(testingDefaultFile, 10);
    CMPMintListProxy.reset();

    BOOST_CHECK_EXCEPTION(
        CMPMintListProxy = CreateCMPMintList(testingDefaultFile, 11),
        std::invalid_argument,
        [] (const std::invalid_argument& e) {
            return std::string("group size input isn't equal to group size in database")
                == e.what();
        }
    );
}

BOOST_AUTO_TEST_SUITE_END()
