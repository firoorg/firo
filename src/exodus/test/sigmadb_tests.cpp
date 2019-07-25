#include <tuple>

#include "exodus/sigmadb.h"

#include <boost/test/unit_test.hpp>

#include <set>

#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "leveldb/db.h"

struct DBTestSetup : TestingSetup
{
    DBTestSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        p_mintlistdb_test = new CMPMintList(pathTemp / "MP_txlist_test", false);
    }
    ~DBTestSetup()
    {
        p_mintlistdb_test->Clear();
    }

    CMPMintList *p_mintlistdb_test;
};

BOOST_FIXTURE_TEST_SUITE(exodus_mint_db_tests, DBTestSetup)

static exodus::SigmaPublicKey GetNewPubcoin()
{
    exodus::SigmaPrivateKey priv;
    priv.Generate();
    return exodus::SigmaPublicKey(priv);
}

static std::vector<exodus::SigmaPublicKey> GetNPubcoins(size_t n)
{
    std::vector<exodus::SigmaPublicKey> pubs;
    while (n-- > 0) {
        pubs.push_back(GetNewPubcoin());
    }
    return pubs;
}

static bool IsAnonymityGroupEqual(
    const std::vector<exodus::SigmaPublicKey>& as,
    const std::vector<exodus::SigmaPublicKey>& bs)
{
    if (as.size() != bs.size()) {
        return false;
    }

    std::set<std::string> commitmentAs, commitmentBs;
    for (auto const& a : as) {
        commitmentAs.insert(a.GetCommitment().GetHex());
    }
    for (auto const& b : bs) {
        commitmentBs.insert(b.GetCommitment().GetHex());
    }
    return commitmentAs == commitmentBs;
}

static std::vector<exodus::SigmaPublicKey> GetFirstN(
    std::vector<exodus::SigmaPublicKey>& org, size_t n)
{
    return std::vector<exodus::SigmaPublicKey>
        (org.begin(), n > org.size() ? org.end() : org.begin() + n);
}

BOOST_AUTO_TEST_CASE(get_set_sequnce)
{
    BOOST_CHECK_EQUAL(0, p_mintlistdb_test->GetNextSequence());
    p_mintlistdb_test->RecordLastSequence(1000);
    BOOST_CHECK_EQUAL(1001, p_mintlistdb_test->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(get_set_mint_count)
{
    struct coinGroup {
        uint32_t groupID;
        uint32_t denom;
        uint32_t group;
    };

    coinGroup groupA{1, 0, 0};
    coinGroup groupB{1, 0, 1};
    coinGroup groupC{2, 0, 0};

    auto setCount = [&] (const coinGroup& g, size_t count) {
        p_mintlistdb_test->RecordMintCount(
            g.groupID, g.denom, g.group, count);
    };

    auto checkCount = [&] (const coinGroup& g, size_t count) -> bool {
        return count == p_mintlistdb_test->GetMintCount(
            g.groupID, g.denom, g.group);
    };

    BOOST_CHECK(checkCount(groupA, 0));
    BOOST_CHECK(checkCount(groupB, 0));
    BOOST_CHECK(checkCount(groupC, 0));

    setCount(groupA, 100);
    setCount(groupA, 105);
    setCount(groupB, 1000);
    setCount(groupC, 0);

    BOOST_CHECK(checkCount(groupA, 105));
    BOOST_CHECK(checkCount(groupB, 1000));
    BOOST_CHECK(checkCount(groupC, 0));
}

BOOST_AUTO_TEST_CASE(get_set_group_id)
{
    struct coinDenom {
        uint32_t propertyID;
        uint32_t denom;
    };

    coinDenom denomA{1, 0};
    coinDenom denomB{1, 1};
    coinDenom denomC{2, 0};

    auto setID = [&] (const coinDenom& d, uint32_t g) {
        p_mintlistdb_test->RecordLastGroupID(
            d.propertyID, d.denom, g);
    };

    auto checkID = [&] (const coinDenom& d, size_t g) -> bool {
        return g == p_mintlistdb_test->GetLastGroupID(
            d.propertyID, d.denom);
    };

    BOOST_CHECK(checkID(denomA, 0));
    BOOST_CHECK(checkID(denomB, 0));
    BOOST_CHECK(checkID(denomC, 0));

    setID(denomA, 1);
    setID(denomA, 2);
    setID(denomB, 4);
    setID(denomC, 0);

    BOOST_CHECK(checkID(denomA, 2));
    BOOST_CHECK(checkID(denomB, 4));
    BOOST_CHECK(checkID(denomC, 0));
}

BOOST_AUTO_TEST_CASE(record_indirect_mint)
{
    BOOST_CHECK_EQUAL(std::string(""),
        p_mintlistdb_test->GetLastMintKeyIndex());

    auto RecordAndCheck = [&] (std::string key, uint32_t expectedNextSequce) {
        p_mintlistdb_test->RecordMintKeyIndex(
        leveldb::Slice(key.data(), key.size()));

        BOOST_CHECK_EQUAL(key,
            p_mintlistdb_test->GetLastMintKeyIndex());

        BOOST_CHECK_EQUAL(expectedNextSequce,
            p_mintlistdb_test->GetNextSequence());
    };

    RecordAndCheck("mintKey1", 1);
    RecordAndCheck("mintKey2", 2);
    RecordAndCheck("mintKey", 3);
}

BOOST_AUTO_TEST_CASE(record_one_coin)
{
    auto mint = GetNewPubcoin();
    uint32_t propID = 1;
    uint32_t denom = 0;

    BOOST_CHECK_EQUAL(0,
        p_mintlistdb_test->GetMintCount(propID, denom, 0));
    BOOST_CHECK_EQUAL(0,
        p_mintlistdb_test->GetNextSequence());

    p_mintlistdb_test->RecordMint(propID, denom, mint, 100);

    BOOST_CHECK_EQUAL(0,
        p_mintlistdb_test->GetLastGroupID(propID, denom));
    BOOST_CHECK_EQUAL(1,
        p_mintlistdb_test->GetMintCount(propID, denom, 0));
    BOOST_CHECK_EQUAL(0,
        p_mintlistdb_test->GetMintCount(propID, denom, 1));
    BOOST_CHECK_EQUAL(1,
        p_mintlistdb_test->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(getmint_notfound)
{
    BOOST_CHECK(
        std::make_pair(exodus::SigmaPublicKey(), int(0)) ==
        p_mintlistdb_test->GetMint(1, 1, 1, 1)
    );
}

BOOST_AUTO_TEST_CASE(getmint_test)
{
    auto mint = GetNewPubcoin();
    uint32_t propID = 1;
    uint32_t denom = 0;
    p_mintlistdb_test->RecordMint(propID, denom, mint, 100);

    BOOST_CHECK(
        std::make_pair(mint, int(100)) ==
        p_mintlistdb_test->GetMint(propID, denom, 0, 0)
    );
}

BOOST_AUTO_TEST_CASE(get_anonymityset_no_anycoin)
{
    BOOST_CHECK_EQUAL(0,
        p_mintlistdb_test->GetAnonimityGroup(0, 0, 0, 100).size());
}

BOOST_AUTO_TEST_CASE(get_anonymityset_have_coin_in_other_group)
{
    auto pubs = GetNPubcoins(10);
    for (auto const &pub : pubs) {
        p_mintlistdb_test->RecordMint(1, 1, pub, 10);
    }
    BOOST_CHECK_EQUAL(0,
        p_mintlistdb_test->GetAnonimityGroup(2, 2, 0, 100).size());
}

BOOST_AUTO_TEST_CASE(get_anonymityset_have_one_group)
{
    auto pubs = GetNPubcoins(10);
    for (auto const &pub : pubs) {
        p_mintlistdb_test->RecordMint(1, 1, pub, 10);
    }

    BOOST_CHECK(IsAnonymityGroupEqual(
        pubs,
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 100)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        pubs,
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 10)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(pubs, 5),
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 5)
    ));
}

BOOST_AUTO_TEST_CASE(get_anonymityset_many_properties)
{
    auto pubs = GetNPubcoins(10);
    for (auto const &pub : pubs) {
        p_mintlistdb_test->RecordMint(1, 1, pub, 10);
    }

    auto property2Pubs = GetNPubcoins(10);
    for (auto const &pub : property2Pubs) {
        p_mintlistdb_test->RecordMint(2, 1, pub, 10);
    }

    BOOST_CHECK(IsAnonymityGroupEqual(
        pubs,
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 100)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        property2Pubs,
        p_mintlistdb_test->GetAnonimityGroup(2, 1, 0, 100)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(pubs, 5),
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 5)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(property2Pubs, 5),
        p_mintlistdb_test->GetAnonimityGroup(2, 1, 0, 5)
    ));
}

BOOST_AUTO_TEST_CASE(get_anonymity_set_many_denominations)
{
    auto pubs = GetNPubcoins(10);
    auto denom2Pubs = GetNPubcoins(10);

    int nBlock = 10;
    for (size_t i = 0; i < pubs.size(); i++) {
        p_mintlistdb_test->RecordMint(1, 1, pubs[i], nBlock);
        p_mintlistdb_test->RecordMint(1, 2, denom2Pubs[i], 10);
        nBlock++;
    }

    BOOST_CHECK(IsAnonymityGroupEqual(
        pubs,
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 100)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        denom2Pubs,
        p_mintlistdb_test->GetAnonimityGroup(1, 2, 0, 100)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(pubs, 5),
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 5)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(denom2Pubs, 5),
        p_mintlistdb_test->GetAnonimityGroup(1, 2, 0, 5)
    ));
}

BOOST_AUTO_TEST_CASE(get_anonymity_set_many_groups)
{
    auto pubs = GetNPubcoins(10);
    for (auto const &pub : pubs) {
        p_mintlistdb_test->RecordMint(1, 1, pub, 10);
    }

    p_mintlistdb_test->RecordLastGroupID(1, 1, 1);

    auto denom2Pubs = GetNPubcoins(10);
    for (auto const &pub : denom2Pubs) {
        p_mintlistdb_test->RecordMint(1, 1, pub, 10);
    }

    BOOST_CHECK(IsAnonymityGroupEqual(
        pubs,
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 100)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        denom2Pubs,
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 1, 100)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(pubs, 5),
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 5)
    ));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(denom2Pubs, 5),
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 1, 5)
    ));
}

BOOST_AUTO_TEST_CASE(delete_an_empty_set_of_coins)
{
    BOOST_CHECK_EQUAL(0, p_mintlistdb_test->GetNextSequence());
    BOOST_CHECK_NO_THROW(p_mintlistdb_test->DeleteAll(1));
    BOOST_CHECK_EQUAL(0, p_mintlistdb_test->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_block_which_have_no_coins)
{
    auto pubs = GetNPubcoins(1);
    p_mintlistdb_test->RecordMint(1, 1, pubs[0], 10); // store at block 10
    BOOST_CHECK_NO_THROW(p_mintlistdb_test->DeleteAll(11)); // delete at block 11
    BOOST_CHECK(IsAnonymityGroupEqual(
        pubs,
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 10)
    ));

    BOOST_CHECK_EQUAL(1, p_mintlistdb_test->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_one_coin)
{
    auto pubs = GetNPubcoins(1);
    p_mintlistdb_test->RecordMint(1, 1, pubs[0], 10);
    BOOST_CHECK_NO_THROW(p_mintlistdb_test->DeleteAll(10));
    BOOST_CHECK(IsAnonymityGroupEqual(
        {},
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 10)
    ));

    BOOST_CHECK_EQUAL(0, p_mintlistdb_test->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_one_of_two_coin)
{
    auto pubs = GetNPubcoins(2);
    p_mintlistdb_test->RecordMint(1, 1, pubs[0], 10); // store at block 10
    p_mintlistdb_test->RecordMint(1, 1, pubs[1], 11); // store at block 11
    BOOST_CHECK_NO_THROW(p_mintlistdb_test->DeleteAll(11)); // delete at block 11
    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(pubs, 1),
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 10)
    ));

    BOOST_CHECK_EQUAL(1, p_mintlistdb_test->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_two_coins_from_two_denominations)
{
    auto pubs = GetNPubcoins(2);
    auto denom2Pubs = GetNPubcoins(2);

    // RecordMint(propertyID, denomination, mint, block)
    p_mintlistdb_test->RecordMint(1, 0, pubs[0], 10);
    p_mintlistdb_test->RecordMint(1, 1, denom2Pubs[0], 10);
    p_mintlistdb_test->RecordMint(1, 0, pubs[1], 11);
    p_mintlistdb_test->RecordMint(1, 1, denom2Pubs[1], 12);

    BOOST_CHECK_EQUAL(4, p_mintlistdb_test->GetNextSequence());

    BOOST_CHECK_NO_THROW(p_mintlistdb_test->DeleteAll(11));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(pubs, 1),
        p_mintlistdb_test->GetAnonimityGroup(1, 0, 0, 10)
    ));
    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(denom2Pubs, 1),
        p_mintlistdb_test->GetAnonimityGroup(1, 1, 0, 10)
    ));

    BOOST_CHECK_EQUAL(2, p_mintlistdb_test->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_two_coins_from_two_properties)
{
    auto pubs = GetNPubcoins(2);
    auto property2Pubs = GetNPubcoins(2);

    // RecordMint(propertyID, denomination, mint, block)
    p_mintlistdb_test->RecordMint(1, 0, pubs[0], 10);
    p_mintlistdb_test->RecordMint(2, 0, property2Pubs[0], 10);
    p_mintlistdb_test->RecordMint(1, 0, pubs[1], 11);
    p_mintlistdb_test->RecordMint(2, 0, property2Pubs[1], 12);

    BOOST_CHECK_EQUAL(4, p_mintlistdb_test->GetNextSequence());

    BOOST_CHECK_NO_THROW(p_mintlistdb_test->DeleteAll(11));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(pubs, 1),
        p_mintlistdb_test->GetAnonimityGroup(1, 0, 0, 10)
    ));
    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(property2Pubs, 1),
        p_mintlistdb_test->GetAnonimityGroup(2, 0, 0, 10)
    ));

    BOOST_CHECK_EQUAL(2, p_mintlistdb_test->GetNextSequence());
}

BOOST_AUTO_TEST_CASE(delete_three_coins_from_two_groups)
{
    auto pubs = GetNPubcoins(2);
    auto group1Pubs = GetNPubcoins(2);
    p_mintlistdb_test->RecordMint(1, 0, pubs[0], 10);
    p_mintlistdb_test->RecordMint(1, 0, pubs[1], 11);

    p_mintlistdb_test->RecordLastGroupID(1, 0, 1);

    p_mintlistdb_test->RecordMint(1, 0, group1Pubs[0], 12);
    p_mintlistdb_test->RecordMint(1, 0, group1Pubs[1], 13);

    BOOST_CHECK_EQUAL(4, p_mintlistdb_test->GetNextSequence());

    BOOST_CHECK_NO_THROW(p_mintlistdb_test->DeleteAll(11));

    BOOST_CHECK(IsAnonymityGroupEqual(
        GetFirstN(pubs, 1),
        p_mintlistdb_test->GetAnonimityGroup(1, 0, 0, 10)
    ));
    BOOST_CHECK(IsAnonymityGroupEqual(
        {},
        p_mintlistdb_test->GetAnonimityGroup(1, 0, 1, 10)
    ));

    BOOST_CHECK_EQUAL(1, p_mintlistdb_test->GetNextSequence());

    // assert last group id of propertyID = 1 and denomination = 0 is decreased to 0
    BOOST_CHECK_EQUAL(0, p_mintlistdb_test->GetLastGroupID(1, 0));
}

BOOST_AUTO_TEST_SUITE_END()