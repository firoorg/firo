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

namespace elysium {

using MintPoolEntry = SigmaWallet::MintPoolEntry;
namespace {

class TestSigmaWalletV1 : public SigmaWalletV1
{

public:
    TestSigmaWalletV1()
    {
    }

public:
    // Proxy
    bool GeneratePublicKey(ECDSAPrivateKey const &priv, secp256k1_pubkey &out)
    {
        return SigmaWalletV1::GeneratePublicKey(priv, out);
    }

    void GenerateSerial(secp256k1_pubkey const &pubkey, secp_primitives::Scalar &serial)
    {
        SigmaWalletV1::GenerateSerial(pubkey, serial);
    }

    using SigmaWalletV1::GeneratePrivateKey;
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed)
    {
        return SigmaWalletV1::GeneratePrivateKey(seed);
    }

    bool WriteElysiumMint(SigmaMintId const &id, SigmaMint const &mint)
    {
        return SigmaWalletV1::WriteElysiumMint(id, mint);
    }

    bool ReadElysiumMint(SigmaMintId const &id, SigmaMint &mint) const
    {
        return SigmaWalletV1::ReadElysiumMint(id, mint);
    }

    bool EraseElysiumMint(SigmaMintId const &id)
    {
        return SigmaWalletV1::EraseElysiumMint(id);
    }

    bool HasElysiumMint(SigmaMintId const &id, CWalletDB *db = nullptr) const
    {
        return SigmaWalletV1::HasElysiumMint(id);
    }

    bool WriteElysiumMintId(uint160 const &hash, SigmaMintId const &mintId)
    {
        return SigmaWalletV1::WriteElysiumMintId(hash, mintId);
    }

    bool ReadElysiumMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db = nullptr) const
    {
        return SigmaWalletV1::ReadElysiumMintId(hash, mintId);
    }

    bool EraseElysiumMintId(uint160 const &hash, CWalletDB *db = nullptr)
    {
        return SigmaWalletV1::EraseElysiumMintId(hash);
    }

    bool HasElysiumMintId(uint160 const &hash, CWalletDB *db = nullptr) const
    {
        return SigmaWalletV1::HasElysiumMintId(hash);
    }

    bool WriteElysiumMintPool(std::vector<MintPoolEntry> const &mints)
    {
        return SigmaWalletV1::WriteElysiumMintPool(mints);
    }

    bool ReadElysiumMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr)
    {
        return SigmaWalletV1::ReadElysiumMintPool(mints);
    }

    void ListElysiumMints(std::function<void(SigmaMintId&, SigmaMint&)> inserter)
    {
        return SigmaWalletV1::ListElysiumMints(inserter);
    }
};

struct SigmaWalletV1TestingSetup : WalletTestingSetup
{
    std::unique_ptr<TestSigmaWalletV1> wallet;

    SigmaWalletV1TestingSetup() : wallet(new TestSigmaWalletV1())
    {
        wallet->ReloadMasterKey();
    }

    std::pair<SigmaMintId, SigmaMint> GenerateMint(elysium::PropertyId id, elysium::SigmaDenomination denom)
    {
        LOCK(pwalletMain->cs_wallet);
        auto seedId = pwalletMain->GenerateNewKey(BIP44_ELYSIUM_MINT_INDEX).GetID();

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

BOOST_FIXTURE_TEST_SUITE(elysium_sigmawalletv1_tests, SigmaWalletV1TestingSetup)

BOOST_AUTO_TEST_CASE(generate_private_key)
{
    uint512 seed;
    seed.SetHex(
        "5ead609e466f37c92b671e3725da4cd98adafdb23496369c09196f30f8d716dc9f67"
        "9026b2f94984f94a289208a2941579ef321dee63d8fd6346ef665c6f60df"
    );

    auto key = wallet->GeneratePrivateKey(seed);

    auto expectedSecret = ParseHex("cb30cc143888ef4e09bb4cfd6d0a699e3c089f42419a8a200132e3190e0e5951");

    BOOST_CHECK_EQUAL(
        std::string("afffcf7021f53224acb46ac82e71013149cd736ee12f6821802f52f9e92b73dd"),
        key.serial.GetHex());

    BOOST_CHECK_EQUAL(
        std::string("d2e5b830ab1fa8235a9af7db4fd554de5757a0e594acbfc1a4526c3fb26bcbbd"),
        key.randomness.GetHex());
}

BOOST_AUTO_TEST_CASE(generate_pubkey)
{
    ECDSAPrivateKey priv;
    auto rawSecret = ParseHex("c634aba3ff562690db4a52cb869d38a43e8d817eddbf68dfb9983af5e9c3e505");
    std::copy(rawSecret.begin(), rawSecret.end(), priv.begin());

    secp256k1_pubkey pubkey;
    wallet->GeneratePublicKey(priv, pubkey);

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

    BOOST_CHECK_EQUAL(true, wallet->WriteElysiumMint(id, mint));
}

BOOST_AUTO_TEST_CASE(read_nonexistmint)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    BOOST_CHECK_EQUAL(false, wallet->HasElysiumMint(id));
    BOOST_CHECK_EQUAL(false, wallet->ReadElysiumMint(id, data));
}

BOOST_AUTO_TEST_CASE(read_existmint)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    wallet->WriteElysiumMint(id, mint);

    BOOST_CHECK_EQUAL(true, wallet->HasElysiumMint(id));
    BOOST_CHECK_EQUAL(true, wallet->ReadElysiumMint(id, data));
    BOOST_CHECK_EQUAL(mint, data);
}

BOOST_AUTO_TEST_CASE(read_erasedmint)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    wallet->WriteElysiumMint(id, mint);
    wallet->EraseElysiumMint(id);

    BOOST_CHECK_EQUAL(false, wallet->HasElysiumMint(id));
    BOOST_CHECK_EQUAL(false, wallet->ReadElysiumMint(id, data));
}

BOOST_AUTO_TEST_CASE(write_mintid)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);
    SigmaMint data;

    BOOST_CHECK_EQUAL(true, wallet->WriteElysiumMintId(mint.serialId, id));
}

BOOST_AUTO_TEST_CASE(read_nonexistmintid)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    BOOST_CHECK_EQUAL(false, wallet->HasElysiumMintId(mint.seedId));
    BOOST_CHECK_EQUAL(false, wallet->ReadElysiumMintId(mint.seedId, data));
}

BOOST_AUTO_TEST_CASE(read_existmintid)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    wallet->WriteElysiumMintId(mint.serialId, id);

    BOOST_CHECK_EQUAL(true, wallet->HasElysiumMintId(mint.serialId));
    BOOST_CHECK_EQUAL(true, wallet->ReadElysiumMintId(mint.serialId, data));
    BOOST_CHECK_EQUAL(id, data);
}

BOOST_AUTO_TEST_CASE(read_erasedmintid)
{
    SigmaMintId id;
    SigmaMint mint;
    std::tie(id, mint) = GenerateMint(3, 0);

    SigmaMintId data;

    wallet->WriteElysiumMintId(mint.serialId, id);
    wallet->EraseElysiumMintId(mint.serialId);

    BOOST_CHECK_EQUAL(false, wallet->HasElysiumMintId(mint.serialId));
    BOOST_CHECK_EQUAL(false, wallet->ReadElysiumMintId(mint.serialId, data));
}

BOOST_AUTO_TEST_CASE(writemintpool)
{
    std::vector<MintPoolEntry> mintPool;

    PopulateMintEntries(3, 0, 10, std::back_inserter(mintPool));

    BOOST_CHECK_EQUAL(true, wallet->WriteElysiumMintPool(mintPool));
}

BOOST_AUTO_TEST_CASE(readmintpool)
{
    std::vector<MintPoolEntry> mintPool;

    PopulateMintEntries(3, 0, 10, std::back_inserter(mintPool));

    wallet->WriteElysiumMintPool(mintPool);

    std::vector<MintPoolEntry> data;
    BOOST_CHECK_EQUAL(true, wallet->ReadElysiumMintPool(data));
    BOOST_CHECK(mintPool == data);
    BOOST_CHECK(std::is_permutation(mintPool.begin(), mintPool.end(), data.begin()));
}

BOOST_AUTO_TEST_CASE(listelysiummints_nomints)
{
    size_t counter = 0;
    wallet->ListElysiumMints([&](SigmaMintId const&, SigmaMint const&) {
        counter++;
    });

    BOOST_CHECK_EQUAL(0, counter);
}

BOOST_AUTO_TEST_CASE(listelysiummints_withsomemints)
{
    std::vector<std::pair<SigmaMintId, SigmaMint>> mints;
    for (size_t i = 0; i < 10; i++)
    {
        SigmaMintId id;
        SigmaMint mint;
        std::tie(id, mint) = GenerateMint(3, 0);

        mints.push_back(std::make_pair(id, mint));

        wallet->WriteElysiumMint(id, mint);
    }

    std::vector<std::pair<SigmaMintId, SigmaMint>> data;
    wallet->ListElysiumMints([&](SigmaMintId &id, SigmaMint &mint) {
        data.push_back(std::make_pair(id, mint));
    });

    BOOST_CHECK(std::is_permutation(mints.begin(), mints.end(), data.begin(), data.end()));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
