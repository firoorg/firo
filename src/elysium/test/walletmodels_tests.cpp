#include "../walletmodels.h"

#include "../../clientversion.h"
#include "../../streams.h"
#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <ostream>

using namespace elysium;

namespace {

SigmaMintId GenerateSigmaMintId(PropertyId property, SigmaDenomination denom)
{
    SigmaPrivateKey priv;
    priv.Generate();
    SigmaPublicKey pub(priv, DefaultSigmaParams);

    return SigmaMintId(property, denom, pub);
}

} // unnamed namespace

namespace std {

template<typename Char, typename Traits, unsigned Size>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const base_blob<Size>& v)
{
    return os << v.GetHex();
}

} // namespace std

namespace elysium {

BOOST_FIXTURE_TEST_SUITE(elysium_walletmodels_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_default)
{
    SigmaMintChainState state;

    BOOST_CHECK_LT(state.block, 0);
    BOOST_CHECK_EQUAL(state.group, 0);
    BOOST_CHECK_EQUAL(state.index, 0);
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_init)
{
    SigmaMintChainState state(100000, 1, 50);

    BOOST_CHECK_EQUAL(state.block, 100000);
    BOOST_CHECK_EQUAL(state.group, 1);
    BOOST_CHECK_EQUAL(state.index, 50);
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_equality)
{
    SigmaMintChainState state(100, 1, 50);

    BOOST_CHECK_EQUAL(state, SigmaMintChainState(100, 1, 50));
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_unequality)
{
    SigmaMintChainState state(100, 1, 50);

    BOOST_CHECK_NE(state, SigmaMintChainState(99, 1, 50));
    BOOST_CHECK_NE(state, SigmaMintChainState(100, 2, 50));
    BOOST_CHECK_NE(state, SigmaMintChainState(100, 1, 60));
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_clear)
{
    SigmaMintChainState state(100, 1, 50);

    state.Clear();

    BOOST_CHECK_EQUAL(state, SigmaMintChainState());
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_serialization)
{
    SigmaMintChainState original(100, 1, 50), deserialized;
    CDataStream stream(SER_DISK, CLIENT_VERSION);

    stream << original;
    stream >> deserialized;

    BOOST_CHECK_EQUAL(deserialized, original);
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_hash)
{
    SigmaMintChainState state1(100, 0, 0), state2(101, 0, 0);
    std::hash<SigmaMintChainState> hasher;

    BOOST_CHECK_EQUAL(hasher(state1), hasher(state1));
    BOOST_CHECK_NE(hasher(state1), hasher(state2));
}

BOOST_AUTO_TEST_CASE(sigma_mint_id_default)
{
    SigmaMintId id;

    BOOST_CHECK_EQUAL(id.property, 0);
    BOOST_CHECK_EQUAL(id.denomination, 0);
    BOOST_CHECK_EQUAL(id.pubKey, SigmaPublicKey());
}

BOOST_AUTO_TEST_CASE(sigma_mint_id_init)
{
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    priv.Generate();
    pub.Generate(priv, DefaultSigmaParams);

    SigmaMintId id(1, 5, pub);

    BOOST_CHECK_EQUAL(id.property, 1);
    BOOST_CHECK_EQUAL(id.denomination, 5);
    BOOST_CHECK_EQUAL(id.pubKey, pub);
}

BOOST_AUTO_TEST_CASE(sigma_mint_id_serialization)
{
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    priv.Generate();
    pub.Generate(priv, DefaultSigmaParams);

    SigmaMintId original(1, 5, pub), deserialized;
    CDataStream stream(SER_DISK, CLIENT_VERSION);

    stream << original;
    stream >> deserialized;

    BOOST_CHECK_EQUAL(deserialized.property, original.property);
    BOOST_CHECK_EQUAL(deserialized.denomination, original.denomination);
    BOOST_CHECK_EQUAL(deserialized.pubKey, original.pubKey);
}

BOOST_AUTO_TEST_CASE(sigma_mint_id_hash)
{
    SigmaMintId id1, id2;
    id1 = GenerateSigmaMintId(3, 0);
    id2 = GenerateSigmaMintId(3, 0);

    std::hash<SigmaMintId> hasher;

    BOOST_CHECK_EQUAL(hasher(id1), hasher(id1));
    BOOST_CHECK_NE(hasher(id1), hasher(id2));
}

BOOST_AUTO_TEST_CASE(sigma_mint_default)
{
    SigmaMint mint;

    BOOST_CHECK_EQUAL(mint.property, 0);
    BOOST_CHECK_EQUAL(mint.denomination, 0);
    BOOST_CHECK_EQUAL(mint.seedId, CKeyID());
    BOOST_CHECK_EQUAL(mint.serialId, uint160());
    BOOST_CHECK_EQUAL(mint.createdTx, uint256());
    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
    BOOST_CHECK_EQUAL(mint.spendTx, uint256());
}

BOOST_AUTO_TEST_CASE(sigma_mint_init)
{
    CKeyID seed;
    uint160 serial;

    seed.SetHex("c20c027ecb57f6bca0e7995f089f2476872ce3c2");
    serial.SetHex("9ef47fe3beb4eca6521644d810f8d82aafa25deb");

    SigmaMint mint(3, 1, seed, serial);

    BOOST_CHECK_EQUAL(mint.property, 3);
    BOOST_CHECK_EQUAL(mint.denomination, 1);
    BOOST_CHECK_EQUAL(mint.seedId, seed);
    BOOST_CHECK_EQUAL(mint.serialId, serial);
    BOOST_CHECK_EQUAL(mint.createdTx, uint256());
    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
    BOOST_CHECK_EQUAL(mint.spendTx, uint256());
}

BOOST_AUTO_TEST_CASE(sigma_mint_equality)
{
    SigmaMint left, right;

    left.property = 1;
    left.denomination = 1;
    left.seedId.SetHex("6b9271111f615f2add38ecca577bd8297cdada76");
    left.serialId.SetHex("e452b723bd12bfcc441e675eedcfad5c8a80435d");
    left.createdTx.SetHex("d256b698c4c1caa75fcbeec68e6636119e02526c58eea91088eba71d9e25e768");
    left.chainState = SigmaMintChainState(500, 1, 50);
    left.spendTx.SetHex("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");

    right.property = 1;
    right.denomination = 1;
    right.seedId.SetHex("6b9271111f615f2add38ecca577bd8297cdada76");
    right.serialId.SetHex("e452b723bd12bfcc441e675eedcfad5c8a80435d");
    right.createdTx.SetHex("d256b698c4c1caa75fcbeec68e6636119e02526c58eea91088eba71d9e25e768");
    right.chainState = SigmaMintChainState(500, 1, 50);
    right.spendTx.SetHex("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");

    BOOST_CHECK_EQUAL(left, right);
}

BOOST_AUTO_TEST_CASE(sigma_mint_unequality)
{
    SigmaMint left, right;

    left.property = 1;
    left.denomination = 1;
    left.seedId.SetHex("6b9271111f615f2add38ecca577bd8297cdada76");
    left.serialId.SetHex("e452b723bd12bfcc441e675eedcfad5c8a80435d");
    left.createdTx.SetHex("d256b698c4c1caa75fcbeec68e6636119e02526c58eea91088eba71d9e25e768");
    left.chainState = SigmaMintChainState(500, 1, 50);
    left.spendTx.SetHex("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");

    // Property.
    right = left;
    right.property = 2;

    BOOST_CHECK_NE(left, right);

    // Denomination.
    right = left;
    right.denomination = 10;

    BOOST_CHECK_NE(left, right);

    // Seed Id
    right = left;
    right.seedId.SetHex("aa53d9c19d2a435e586c5539e5696b9e0b49600a");

    BOOST_CHECK_NE(left, right);

    // Serial Id
    right = left;
    right.serialId.SetHex("aa53d9c19d2a435e586c5539e5696b9e0b49600a");

    BOOST_CHECK_NE(left, right);

    // Created TX.
    right = left;
    right.createdTx.SetHex("4feba033ccba0e98c48359e1974ef3257127cc1794baaa2a66f3773b42a313dd");

    BOOST_CHECK_NE(left, right);

    // Chain State
    right = left;
    right.chainState = SigmaMintChainState(1000, 0, 0);

    BOOST_CHECK_NE(left, right);

    // Spend Tx
    right = left;
    right.spendTx.SetHex("4feba033ccba0e98c48359e1974ef3257127cc1794baaa2a66f3773b42a313dd");

    BOOST_CHECK_NE(left, right);
}

BOOST_AUTO_TEST_CASE(sigma_mint_is_on_chain)
{
    SigmaMint mint;

    BOOST_CHECK_EQUAL(mint.IsOnChain(), false);

    mint.chainState.block = 0;

    BOOST_CHECK_EQUAL(mint.IsOnChain(), true);

    mint.chainState.block = 1;

    BOOST_CHECK_EQUAL(mint.IsOnChain(), true);
}

BOOST_AUTO_TEST_CASE(sigma_mint_is_spent)
{
    SigmaMint mint;

    BOOST_CHECK_EQUAL(mint.IsSpent(), false);

    mint.spendTx.SetHex("4feba033ccba0e98c48359e1974ef3257127cc1794baaa2a66f3773b42a313dd");

    BOOST_CHECK_EQUAL(mint.IsSpent(), true);
}

BOOST_AUTO_TEST_CASE(sigma_mint_serialization)
{
    SigmaMint original, deserialized;

    original.property = 1;
    original.denomination = 1;
    original.seedId.SetHex("d301a80ac8e079cfed60c361004caadc049052dd");
    original.serialId.SetHex("7b05ea12b56e60b28e2d20db6d77a95f56ae13bb");
    original.createdTx.SetHex("ddf5fb2d1124bcff2f2068334de61f6cc8849d7751a64a74900dbbec106ba884");
    original.chainState = SigmaMintChainState(500, 1, 50);
    original.spendTx.SetHex("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");

    CDataStream stream(SER_DISK, CLIENT_VERSION);

    stream << original;
    stream >> deserialized;

    BOOST_CHECK_EQUAL(deserialized, original);
}

BOOST_AUTO_TEST_CASE(sigma_mint_hash)
{
    SigmaMint mint1, mint2;

    mint1.denomination = 0;
    mint2.denomination = 1;

    std::hash<SigmaMint> hasher;

    BOOST_CHECK_EQUAL(hasher(mint1), hasher(mint1));
    BOOST_CHECK_NE(hasher(mint1), hasher(mint2));
}

BOOST_AUTO_TEST_CASE(sigma_spend_init)
{
    auto& params = DefaultSigmaParams;
    SigmaPrivateKey key1, key2;
    key1.Generate();
    key2.Generate();

    SigmaPublicKey pub1(key1, params), pub2(key2, params);

    SigmaMintId id(3, 0, pub1);
    SigmaMint mint(3, 0, Hash160({0x00}), Hash160({0x01}));

    std::vector<SigmaPublicKey> anonimitySet = { pub1, pub2 };
    SigmaProof proof(params, key1, anonimitySet.begin(), anonimitySet.end(), false);
    SigmaSpend spend(id, 1, 100, proof);

    BOOST_CHECK_EQUAL(spend.mint, id);
    BOOST_CHECK_EQUAL(spend.group, 1);
    BOOST_CHECK_EQUAL(spend.groupSize, 100);
    BOOST_CHECK_EQUAL(spend.proof, proof);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
