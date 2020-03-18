// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../sigmadb.h"
#include "../sigmawalletv0.h"
#include "../walletmodels.h"

#include "../../key.h"
#include "../../main.h"
#include "../../utiltime.h"
#include "../../validationinterface.h"

#include "../../rpc/server.h"

#include "../../wallet/db.h"
#include "../../wallet/rpcwallet.h"
#include "../../wallet/wallet.h"
#include "../../wallet/walletdb.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>
#include <boost/function_output_iterator.hpp>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace std {

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const vector<SigmaMintId>& mints)
{
    vector<basic_string<Char, Traits>> strings;

    for (auto& m : mints) {
        basic_stringstream<Char, Traits> s;
        s << m;
        strings.push_back(s.str());
    }

    return os << '[' << boost::algorithm::join(strings, ", ") << ']';
}

} // namespace std

namespace elysium {

using MintPoolEntry = SigmaWallet::MintPoolEntry;

namespace {

class TestSigmaWalletV0 : public SigmaWalletV0
{

public:
    TestSigmaWalletV0()
    {
    }

public:
    // Proxy
    using SigmaWalletV0::GeneratePrivateKey;

    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed)
    {
        return SigmaWalletV0::GeneratePrivateKey(seed);
    }

    SigmaWallet::Database* GetDB()
    {
        return this->database.get();
    }
};

struct SigmaWalletV0TestingSetup : WalletTestingSetup
{
    std::unique_ptr<TestSigmaWalletV0> wallet;

    SigmaWalletV0TestingSetup() : wallet(new TestSigmaWalletV0())
    {
        wallet->ReloadMasterKey();
    }

    std::pair<SigmaMintId, SigmaMint> GenerateMint(elysium::PropertyId id, elysium::SigmaDenomination denom)
    {
        LOCK(pwalletMain->cs_wallet);
        auto seedId = pwalletMain->GenerateNewKey(BIP44_ELYSIUM_MINT_INDEX_V0).GetID();

        auto priv = wallet->GeneratePrivateKey(seedId);
        SigmaPublicKey pub(priv, DefaultSigmaParams);

        auto serialId = GetSerialId(priv.serial);

        return std::make_pair(
            SigmaMintId(id, denom, pub),
            SigmaMint(id, denom, seedId, serialId));
    }

    std::pair<elysium::SigmaPrivateKey, elysium::SigmaPublicKey> GetKey(CKeyID const &id)
    {
        LOCK(pwalletMain->cs_wallet);
        auto priv = wallet->GeneratePrivateKey(id);
        SigmaPublicKey pub(priv, DefaultSigmaParams);

        return std::make_pair(priv, pub);
    }

    template<class Output>
    bool PopulateMintEntries(PropertyId propId, SigmaDenomination denom, size_t amount, Output output)
    {
        for (size_t i = 0; i < amount; i++) {
            SigmaMintId id;
            SigmaMint mint;
            std::tie(id, mint) = GenerateMint(propId, denom);

            auto key = GetKey(mint.seedId);

            *output++ = MintPoolEntry(key.second, mint.seedId, i);
        }
    }
};

} // unnamed namespace

BOOST_FIXTURE_TEST_SUITE(elysium_sigmawalletv0_tests, SigmaWalletV0TestingSetup)

BOOST_AUTO_TEST_CASE(generate_private_key)
{
    uint512 seed;
    seed.SetHex(
        "5ead609e466f37c92b671e3725da4cd98adafdb23496369c09196f30f8d716dc9f67"
        "9026b2f94984f94a289208a2941579ef321dee63d8fd6346ef665c6f60df"
    );

    auto key = wallet->GeneratePrivateKey(seed);

    BOOST_CHECK_EQUAL(
        std::string("cb30cc143888ef4e09bb4cfd6d0a699e3c089f42419a8a200132e3190e0e5951"),
        key.serial.GetHex());

    BOOST_CHECK_EQUAL(
        std::string("d2e5b830ab1fa8235a9af7db4fd554de5757a0e594acbfc1a4526c3fb26bcbbd"),
        key.randomness.GetHex());
}

BOOST_AUTO_TEST_CASE(writemint)
{
    auto db = wallet->GetDB();

    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    BOOST_CHECK_EQUAL(true, db->WriteMint(id, mint));
}

BOOST_AUTO_TEST_CASE(read_nonexistmint)
{
    auto db = wallet->GetDB();

    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    BOOST_CHECK_EQUAL(false, db->HasMint(id));
    BOOST_CHECK_EQUAL(false, db->ReadMint(id, data));
}

BOOST_AUTO_TEST_CASE(read_existmint)
{
    auto db = wallet->GetDB();

    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    db->WriteMint(id, mint);

    BOOST_CHECK_EQUAL(true, db->HasMint(id));
    BOOST_CHECK_EQUAL(true, db->ReadMint(id, data));
    BOOST_CHECK_EQUAL(mint, data);
}

BOOST_AUTO_TEST_CASE(read_erasedmint)
{
    auto db = wallet->GetDB();

    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    db->WriteMint(id, mint);
    db->EraseMint(id);

    BOOST_CHECK_EQUAL(false, db->HasMint(id));
    BOOST_CHECK_EQUAL(false, db->ReadMint(id, data));
}

BOOST_AUTO_TEST_CASE(write_mintid)
{
    auto db = wallet->GetDB();

    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    BOOST_CHECK_EQUAL(true, db->WriteMintId(mint.serialId, id));
}

BOOST_AUTO_TEST_CASE(read_nonexistmintid)
{
    auto db = wallet->GetDB();

    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    BOOST_CHECK_EQUAL(false, db->HasMintId(mint.seedId));
    BOOST_CHECK_EQUAL(false, db->ReadMintId(mint.seedId, data));
}

BOOST_AUTO_TEST_CASE(read_existmintid)
{
    auto db = wallet->GetDB();

    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    db->WriteMintId(mint.serialId, id);

    BOOST_CHECK_EQUAL(true, db->HasMintId(mint.serialId));
    BOOST_CHECK_EQUAL(true, db->ReadMintId(mint.serialId, data));
    BOOST_CHECK_EQUAL(id, data);
}

BOOST_AUTO_TEST_CASE(read_erasedmintid)
{
    auto db = wallet->GetDB();

    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    db->WriteMintId(mint.serialId, id);
    db->EraseMintId(mint.serialId);

    BOOST_CHECK_EQUAL(false, db->HasMintId(mint.serialId));
    BOOST_CHECK_EQUAL(false, db->ReadMintId(mint.serialId, data));
}

BOOST_AUTO_TEST_CASE(writemintpool)
{
    auto db = wallet->GetDB();

    std::vector<MintPoolEntry> mintPool;

    PopulateMintEntries(3, 0, 10, std::back_inserter(mintPool));

    BOOST_CHECK_EQUAL(true, db->WriteMintPool(mintPool));
}

BOOST_AUTO_TEST_CASE(readmintpool)
{
    auto db = wallet->GetDB();

    std::vector<MintPoolEntry> mintPool;

    PopulateMintEntries(3, 0, 10, std::back_inserter(mintPool));

    db->WriteMintPool(mintPool);

    std::vector<MintPoolEntry> data;
    BOOST_CHECK_EQUAL(true, db->ReadMintPool(data));
    BOOST_CHECK(mintPool == data);
    BOOST_CHECK(std::is_permutation(mintPool.begin(), mintPool.end(), data.begin()));
}

BOOST_AUTO_TEST_CASE(listmints_nomints)
{
    auto db = wallet->GetDB();

    size_t counter = 0;
    db->ListMints([&](SigmaMintId const&, SigmaMint const&) {
        counter++;
    });

    BOOST_CHECK_EQUAL(0, counter);
}

BOOST_AUTO_TEST_CASE(listmints_withsomemints)
{
    auto db = wallet->GetDB();

    std::vector<std::pair<SigmaMintId, SigmaMint>> mints;
    for (size_t i = 0; i < 10; i++) {
        SigmaMintId id;
        SigmaMint mint;
        std::tie(id, mint) = GenerateMint(3, 0);

        mints.push_back(std::make_pair(id, mint));

        db->WriteMint(id, mint);
    }

    std::vector<std::pair<SigmaMintId, SigmaMint>> data;
    db->ListMints([&](SigmaMintId &id, SigmaMint &mint) {
        data.push_back(std::make_pair(id, mint));
    });

    BOOST_CHECK(std::is_permutation(mints.begin(), mints.end(), data.begin(), data.end()));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
