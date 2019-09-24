#include "../walletmodels.h"

#include "../../clientversion.h"
#include "../../streams.h"
#include "../../test/test_bitcoin.h"
#include "../../primitives/zerocoin.h"

#include <boost/test/unit_test.hpp>

namespace exodus {

SigmaMintId GenerateSigmaMintId(PropertyId property, SigmaDenomination denom)
{
    SigmaPrivateKey priv;
    priv.Generate();
    SigmaPublicKey pub(priv, DefaultSigmaParams);

    return SigmaMintId(property, denom, pub);
}

BOOST_FIXTURE_TEST_SUITE(exodus_walletmodels_tests, BasicTestingSetup)

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
    id1 = GenerateSigmaMintId(0, 3);
    id2 = GenerateSigmaMintId(0, 3);

    std::hash<SigmaMintId> hasher;

    BOOST_CHECK_EQUAL(hasher(id1), hasher(id1));
    BOOST_CHECK_NE(hasher(id1), hasher(id2));
}

BOOST_AUTO_TEST_CASE(sigma_mint_default)
{
    SigmaMint mint;

    BOOST_CHECK(mint.spendTx.IsNull());
    BOOST_CHECK_EQUAL(mint.property, 0);
    BOOST_CHECK_EQUAL(mint.denomination, 0);
    // BOOST_CHECK_EQUAL(mint.spendTx, uint256());
    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
}

BOOST_AUTO_TEST_CASE(sigma_mint_equality)
{
    auto tx = uint256S("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");
    SigmaPrivateKey key;
    key.Generate();
    SigmaPublicKey pub(key, DefaultSigmaParams);

    SigmaMint left, right;

    left.property = 1;
    left.denomination = 1;
    left.seedId = uint160();
    left.serialId = primitives::GetSerialHash160(key.serial);
    left.spendTx = tx;
    left.chainState = SigmaMintChainState(500, 1, 50);

    right.property = 1;
    right.denomination = 1;
    right.seedId = uint160();
    right.serialId = primitives::GetSerialHash160(key.serial);
    right.spendTx = tx;
    right.chainState = SigmaMintChainState(500, 1, 50);

    BOOST_CHECK_EQUAL(left, right);
}

BOOST_AUTO_TEST_CASE(sigma_mint_unequality)
{
    SigmaPrivateKey priv;
    priv.Generate();
    SigmaPublicKey pub(priv, DefaultSigmaParams);

    std::vector<unsigned char> zero = {0x00};
    std::vector<unsigned char> one = {0x01};

    SigmaMint left, right;

    left.property = 1;
    left.denomination = 1;
    left.seedId = Hash160(zero);
    left.serialId = Hash160(zero);
    left.spendTx = uint256S("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");
    left.chainState = SigmaMintChainState(500, 1, 50);

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
    right.seedId = Hash160(one);

    BOOST_CHECK_NE(left, right);

    // Serial Id
    right = left;
    right.serialId = Hash160(one);

    BOOST_CHECK_NE(left, right);

    // Spend Tx
    right = left;
    right.spendTx = uint256();

    BOOST_CHECK_NE(left, right);

    // Block
    right = left;
    right.chainState.block = 501;

    BOOST_CHECK_NE(left, right);

    // Group
    right = left;
    right.chainState.group = 2;

    BOOST_CHECK_NE(left, right);

    // Index
    right = left;
    right.chainState.index = 51;

    BOOST_CHECK_NE(left, right);
}

BOOST_AUTO_TEST_CASE(sigma_mint_serialization)
{
    SigmaMint original, deserialized;

    SigmaPrivateKey priv;
    priv.Generate();
    SigmaPublicKey pub(priv, DefaultSigmaParams);

    original.property = 1;
    original.denomination = 1;
    original.seedId = Hash160({0x00});
    original.serialId = Hash160({0x00});
    original.spendTx = uint256S("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");
    original.chainState = SigmaMintChainState(500, 1, 50);

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
    SigmaProof proof(params, key1, anonimitySet.begin(), anonimitySet.end());
    SigmaSpend spend(id, 1, 100, proof);

    BOOST_CHECK_EQUAL(spend.mint, id);
    BOOST_CHECK_EQUAL(spend.group, 1);
    BOOST_CHECK_EQUAL(spend.groupSize, 100);
    BOOST_CHECK_EQUAL(spend.proof, proof);
}

BOOST_AUTO_TEST_SUITE_END()

}
