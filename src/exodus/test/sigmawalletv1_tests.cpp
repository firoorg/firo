// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../sigmadb.h"
#include "../sigmawalletv1.h"
#include "../walletmodels.h"

#include "../../key.h"
#include "../../main.h"
#include "../../utiltime.h"
#include "../../validationinterface.h"

#include "../../rpc/server.h"
#include "../../sigma/openssl_context.h"

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

namespace exodus {
namespace {

class TestSigmaWalletV1 : public SigmaWalletV1
{

public:
    TestSigmaWalletV1()
    {
    }

public:
    // Proxy
    bool GeneratePublicKey(unsigned char const *priv, size_t privSize, secp256k1_pubkey &out)
    {
        return SigmaWalletV1::GeneratePublicKey(priv, privSize, out);
    }

    void GenerateSerial(secp256k1_pubkey const &pubkey, secp_primitives::Scalar &serial)
    {
        SigmaWalletV1::GenerateSerial(pubkey, serial);
    }

    using SigmaWalletV1::GeneratePrivateKey;
    SigmaPrivateKeyV1 GeneratePrivateKey(uint512 const &seed)
    {
        return SigmaWalletV1::GeneratePrivateKey(seed);
    }

    bool WriteExodusMint(SigmaMintId const &id, SigmaMint const &mint)
    {
        return SigmaWalletV1::WriteExodusMint(id, mint);
    }

    bool ReadExodusMint(SigmaMintId const &id, SigmaMint &mint) const
    {
        return SigmaWalletV1::ReadExodusMint(id, mint);
    }

    bool EraseExodusMint(SigmaMintId const &id)
    {
        return SigmaWalletV1::EraseExodusMint(id);
    }

    bool HasExodusMint(SigmaMintId const &id, CWalletDB *db = nullptr) const
    {
        return SigmaWalletV1::HasExodusMint(id);
    }

    bool WriteExodusMintId(uint160 const &hash, SigmaMintId const &mintId)
    {
        return SigmaWalletV1::WriteExodusMintId(hash, mintId);
    }

    bool ReadExodusMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db = nullptr) const
    {
        return SigmaWalletV1::ReadExodusMintId(hash, mintId);
    }

    bool EraseExodusMintId(uint160 const &hash, CWalletDB *db = nullptr)
    {
        return SigmaWalletV1::EraseExodusMintId(hash);
    }

    bool HasExodusMintId(uint160 const &hash, CWalletDB *db = nullptr) const
    {
        return SigmaWalletV1::HasExodusMintId(hash);
    }

    bool WriteExodusMintPool(std::vector<MintPoolEntry> const &mints)
    {
        return SigmaWalletV1::WriteExodusMintPool(mints);
    }

    bool ReadExodusMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr)
    {
        return SigmaWalletV1::ReadExodusMintPool(mints);
    }

    void ListExodusMints(std::function<void(SigmaMintId&, SigmaMint&)> inserter)
    {
        return SigmaWalletV1::ListExodusMints(inserter);
    }
};

struct SigmaWalletV1TestingSetup : WalletTestingSetup
{
    std::unique_ptr<TestSigmaWalletV1> wallet;

    SigmaWalletV1TestingSetup() : wallet(new TestSigmaWalletV1())
    {
        wallet->ReloadMasterKey();
    }

    std::pair<SigmaMintId, SigmaMint> GenerateMint(exodus::PropertyId id, exodus::SigmaDenomination denom)
    {
        LOCK(pwalletMain->cs_wallet);
        auto seedId = pwalletMain->GenerateNewKey(BIP44_EXODUS_MINT_INDEX).GetID();

        auto priv = wallet->GeneratePrivateKey(seedId);
        SigmaPublicKey pub(priv, DefaultSigmaParams);

        auto serialId = GetSerialId(priv.serial);

        return std::make_pair(
            SigmaMintId(id, denom, pub),
            SigmaMint(id, denom, seedId, serialId));
    }

    std::pair<exodus::SigmaPrivateKeyV1, exodus::SigmaPublicKey> GetKey(CKeyID const &id)
    {
        LOCK(pwalletMain->cs_wallet);
        auto priv = wallet->GeneratePrivateKey(id);
        SigmaPublicKey pub(priv, DefaultSigmaParams);

        return std::make_pair(priv, pub);
    }

    template<class Output>
    bool PopulateMintEntries(PropertyId propId, SigmaDenomination denom, size_t amount, Output output)
    {
        for (size_t i = 0; i < amount; i++)
        {
            SigmaMintId id;
            SigmaMint mint;
            std::tie(id, mint) = GenerateMint(propId, denom);

            SigmaMintId data;

            auto key = GetKey(mint.seedId);

            output++ = MintPoolEntry(key.second, mint.seedId, i);
        }
    }
};

} // unnamed namespace

BOOST_FIXTURE_TEST_SUITE(exodus_sigmawalletv1_tests, SigmaWalletV1TestingSetup)

BOOST_AUTO_TEST_CASE(generate_private_key)
{
    uint512 seed;
    seed.SetHex(
        "5ead609e466f37c92b671e3725da4cd98adafdb23496369c09196f30f8d716dc9f67"
        "9026b2f94984f94a289208a2941579ef321dee63d8fd6346ef665c6f60df"
    );

    auto key = wallet->GeneratePrivateKey(seed);

    auto expectedSecret = ParseHex("cb30cc143888ef4e09bb4cfd6d0a699e3c089f42419a8a200132e3190e0e5951");

    BOOST_CHECK_EQUAL_COLLECTIONS(
        expectedSecret.data(), expectedSecret.data() + expectedSecret.size(), &key.ecdsaPrivkey[0], &key.ecdsaPrivkey[0] + sizeof(key.ecdsaPrivkey));

    BOOST_CHECK_EQUAL(
        std::string("afffcf7021f53224acb46ac82e71013149cd736ee12f6821802f52f9e92b73dd"),
        key.serial.GetHex());

    BOOST_CHECK_EQUAL(
        std::string("d2e5b830ab1fa8235a9af7db4fd554de5757a0e594acbfc1a4526c3fb26bcbbd"),
        key.randomness.GetHex());
}

BOOST_AUTO_TEST_CASE(generate_pubkey)
{
    auto secret = ParseHex("c634aba3ff562690db4a52cb869d38a43e8d817eddbf68dfb9983af5e9c3e505");

    secp256k1_pubkey pubkey;
    wallet->GeneratePublicKey(secret.data(), secret.size(), pubkey);

    std::array<uint8_t, 33> compressedPub;

    size_t outSize = sizeof(compressedPub);
    secp256k1_ec_pubkey_serialize(
        OpenSSLContext::get_context(),
        compressedPub.begin(),
        &outSize,
        &pubkey,
        SECP256K1_EC_COMPRESSED);

    BOOST_CHECK_EQUAL(
        std::string("02dce8866a065822ede68f54040342dafb55328fc666e2cbe5b37c56ebe5195ca1"),
        HexStr(compressedPub));
}

BOOST_AUTO_TEST_CASE(generate_serial)
{
    auto rawPubkey = ParseHex("02dce8866a065822ede68f54040342dafb55328fc666e2cbe5b37c56ebe5195ca1");

    secp256k1_pubkey pubkey;
    BOOST_CHECK(secp256k1_ec_pubkey_parse(
        OpenSSLContext::get_context(),
        &pubkey,
        rawPubkey.data(),
        rawPubkey.size()
    ));

    secp_primitives::Scalar serial;
    wallet->GenerateSerial(pubkey, serial);

    BOOST_CHECK_EQUAL(
        std::string("b8394f96f9aedc8a00091bf2e4dc639eb54af823477afac4dd89db23657c5576"),
        serial.GetHex());
}

BOOST_AUTO_TEST_CASE(writemint)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    BOOST_CHECK_EQUAL(true, wallet->WriteExodusMint(id, mint));
}

BOOST_AUTO_TEST_CASE(read_nonexistmint)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    BOOST_CHECK_EQUAL(false, wallet->HasExodusMint(id));
    BOOST_CHECK_EQUAL(false, wallet->ReadExodusMint(id, data));
}

BOOST_AUTO_TEST_CASE(read_existmint)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    wallet->WriteExodusMint(id, mint);

    BOOST_CHECK_EQUAL(true, wallet->HasExodusMint(id));
    BOOST_CHECK_EQUAL(true, wallet->ReadExodusMint(id, data));
    BOOST_CHECK_EQUAL(mint, data);
}

BOOST_AUTO_TEST_CASE(read_erasedmint)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    wallet->WriteExodusMint(id, mint);
    wallet->EraseExodusMint(id);

    BOOST_CHECK_EQUAL(false, wallet->HasExodusMint(id));
    BOOST_CHECK_EQUAL(false, wallet->ReadExodusMint(id, data));
}

BOOST_AUTO_TEST_CASE(write_mintid)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    BOOST_CHECK_EQUAL(true, wallet->WriteExodusMintId(mint.serialId, id));
}

BOOST_AUTO_TEST_CASE(read_nonexistmintid)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    BOOST_CHECK_EQUAL(false, wallet->HasExodusMintId(mint.seedId));
    BOOST_CHECK_EQUAL(false, wallet->ReadExodusMintId(mint.seedId, data));
}

BOOST_AUTO_TEST_CASE(read_existmintid)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    wallet->WriteExodusMintId(mint.serialId, id);

    BOOST_CHECK_EQUAL(true, wallet->HasExodusMintId(mint.serialId));
    BOOST_CHECK_EQUAL(true, wallet->ReadExodusMintId(mint.serialId, data));
    BOOST_CHECK_EQUAL(id, data);
}

BOOST_AUTO_TEST_CASE(read_erasedmintid)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    wallet->WriteExodusMintId(mint.serialId, id);
    wallet->EraseExodusMintId(mint.serialId);

    BOOST_CHECK_EQUAL(false, wallet->HasExodusMintId(mint.serialId));
    BOOST_CHECK_EQUAL(false, wallet->ReadExodusMintId(mint.serialId, data));
}

BOOST_AUTO_TEST_CASE(writemintpool)
{
    std::vector<MintPoolEntry> mintPool;

    PopulateMintEntries(3, 0, 10, std::back_inserter(mintPool));

    BOOST_CHECK_EQUAL(true, wallet->WriteExodusMintPool(mintPool));
}

BOOST_AUTO_TEST_CASE(readmintpool)
{
    std::vector<MintPoolEntry> mintPool;

    PopulateMintEntries(3, 0, 10, std::back_inserter(mintPool));

    wallet->WriteExodusMintPool(mintPool);

    std::vector<MintPoolEntry> data;
    BOOST_CHECK_EQUAL(true, wallet->ReadExodusMintPool(data));
    BOOST_CHECK(mintPool == data);
    BOOST_CHECK(std::is_permutation(mintPool.begin(), mintPool.end(), data.begin()));
}

BOOST_AUTO_TEST_CASE(listexodusmints_nomints)
{
    size_t counter = 0;
    wallet->ListExodusMints([&](SigmaMintId const&, SigmaMint const&) {
        counter++;
    });

    BOOST_CHECK_EQUAL(0, counter);
}

BOOST_AUTO_TEST_CASE(listexodusmints_withsomemints)
{
    std::vector<std::pair<SigmaMintId, SigmaMint>> mints;
    for (size_t i = 0; i < 10; i++)
    {
        SigmaMintId id;
        SigmaMint mint;
        std::tie(id, mint) = GenerateMint(3, 0);

        mints.push_back(std::make_pair(id, mint));

        wallet->WriteExodusMint(id, mint);
    }

    std::vector<std::pair<SigmaMintId, SigmaMint>> data;
    wallet->ListExodusMints([&](SigmaMintId &id, SigmaMint &mint) {
        data.push_back(std::make_pair(id, mint));
    });

    BOOST_CHECK(std::is_permutation(mints.begin(), mints.end(), data.begin(), data.end()));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace exodus
