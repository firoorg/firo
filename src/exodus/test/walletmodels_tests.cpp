#include "../walletmodels.h"

#include "../../clientversion.h"
#include "../../streams.h"
#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace exodus {

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
    BOOST_CHECK_EQUAL(id.key, SigmaPublicKey());
}

BOOST_AUTO_TEST_CASE(sigma_mint_id_from_mint)
{
    SigmaMint mint(1, 5);
    SigmaMintId id(mint);

    BOOST_CHECK_EQUAL(id.property, 1);
    BOOST_CHECK_EQUAL(id.denomination, 5);
    BOOST_CHECK_EQUAL(id.key, SigmaPublicKey(mint.key));
}

BOOST_AUTO_TEST_CASE(sigma_mint_id_init)
{
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    priv.Generate();
    pub.Generate(priv);

    SigmaMintId id(1, 5, pub);

    BOOST_CHECK_EQUAL(id.property, 1);
    BOOST_CHECK_EQUAL(id.denomination, 5);
    BOOST_CHECK_EQUAL(id.key, pub);
}

BOOST_AUTO_TEST_CASE(sigma_mint_id_serialization)
{
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    priv.Generate();
    pub.Generate(priv);

    SigmaMintId original(1, 5, pub), deserialized;
    CDataStream stream(SER_DISK, CLIENT_VERSION);

    stream << original;
    stream >> deserialized;

    BOOST_CHECK_EQUAL(deserialized.property, original.property);
    BOOST_CHECK_EQUAL(deserialized.denomination, original.denomination);
    BOOST_CHECK_EQUAL(deserialized.key, original.key);
}

BOOST_AUTO_TEST_CASE(sigma_mint_id_hash)
{
    SigmaMint mint1(3, 0), mint2(3, 0);
    SigmaMintId id1(mint1), id2(mint2);
    std::hash<SigmaMintId> hasher;

    BOOST_CHECK_EQUAL(hasher(id1), hasher(id1));
    BOOST_CHECK_NE(hasher(id1), hasher(id2));
}

BOOST_AUTO_TEST_CASE(sigma_mint_default)
{
    SigmaMint mint;

    BOOST_CHECK(mint.spentTx.IsNull());
    BOOST_CHECK_EQUAL(mint.property, 0);
    BOOST_CHECK_EQUAL(mint.denomination, 0);
    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
    BOOST_CHECK_EQUAL(mint.key, SigmaPrivateKey());
}

BOOST_AUTO_TEST_CASE(sigma_mint_generate)
{
    SigmaMint mint(1, 5);

    BOOST_CHECK(mint.spentTx.IsNull());
    BOOST_CHECK_EQUAL(mint.property, 1);
    BOOST_CHECK_EQUAL(mint.denomination, 5);
    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
    BOOST_CHECK_NE(mint.key, SigmaPrivateKey());
}

BOOST_AUTO_TEST_CASE(sigma_mint_equality)
{
    auto tx = uint256S("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");
    SigmaPrivateKey key;
    SigmaMint left, right;

    key.Generate();

    left.spentTx = tx;
    left.property = 1;
    left.denomination = 1;
    left.chainState.block = 500;
    left.chainState.group = 1;
    left.chainState.index = 50;
    left.key = key;

    right.spentTx = tx;
    right.property = 1;
    right.denomination = 1;
    right.chainState.block = 500;
    right.chainState.group = 1;
    right.chainState.index = 50;
    right.key = key;

    BOOST_CHECK_EQUAL(left, right);
}

BOOST_AUTO_TEST_CASE(sigma_mint_unequality)
{
    SigmaMint left, right;

    left.spentTx = uint256S("e84390b1e9af85fed8ef3f95d6f94550e53a8a9214677a4b5cae9e93888537ab");
    left.property = 1;
    left.denomination = 1;
    left.chainState.block = 500;
    left.chainState.group = 1;
    left.chainState.index = 50;
    left.key.Generate();

    // Spent Tx.
    right = left;
    right.spentTx.SetNull();

    BOOST_CHECK_NE(left, right);

    // Property.
    right = left;
    right.property = 2;

    BOOST_CHECK_NE(left, right);

    // Denomination.
    right = left;
    right.denomination = 10;

    BOOST_CHECK_NE(left, right);

    // Chain state.
    right = left;
    right.chainState.Clear();

    BOOST_CHECK_NE(left, right);

    // Key.
    right = left;
    right.key.Generate();

    BOOST_CHECK_NE(left, right);
}

BOOST_AUTO_TEST_CASE(sigma_mint_serialization)
{
    SigmaMint original(1, 1), deserialized;
    CDataStream stream(SER_DISK, CLIENT_VERSION);

    stream << original;
    stream >> deserialized;

    BOOST_CHECK_EQUAL(deserialized, original);
}

BOOST_AUTO_TEST_CASE(sigma_mint_hash)
{
    SigmaMint mint1(3, 0), mint2(3, 0);
    std::hash<SigmaMint> hasher;

    BOOST_CHECK_EQUAL(hasher(mint1), hasher(mint1));
    BOOST_CHECK_NE(hasher(mint1), hasher(mint2));
}

BOOST_AUTO_TEST_SUITE_END()

}
