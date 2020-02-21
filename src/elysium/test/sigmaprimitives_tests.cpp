#include "../sigmaprimitives.h"

#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <vector>

namespace elysium {

BOOST_FIXTURE_TEST_SUITE(elysium_sigmaprimitives_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(params)
{
    auto g = secp_primitives::GroupElement().set_base_g();
    SigmaParams params(g, 7, 4);

    BOOST_CHECK_EQUAL(params.g, g);
    BOOST_CHECK_EQUAL(params.m, 7);
    BOOST_CHECK_EQUAL(params.n, 4);
    BOOST_CHECK_EQUAL(params.h.size(), 7 * 4);
}

BOOST_AUTO_TEST_CASE(params_validation)
{
    BOOST_CHECK_THROW(SigmaParams(secp_primitives::GroupElement().set_base_g(), 0, 1), std::invalid_argument);
    BOOST_CHECK_THROW(SigmaParams(secp_primitives::GroupElement().set_base_g(), 1, 0), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(private_key)
{
    SigmaPrivateKey key;

    auto serial = key.serial;
    auto randomness = key.randomness;

    key.Generate();

    BOOST_CHECK(key.IsValid());
    BOOST_CHECK_NE(key.serial, serial);
    BOOST_CHECK_NE(key.randomness, randomness);
}

BOOST_AUTO_TEST_CASE(private_key_hash)
{
    SigmaPrivateKey key1, key2;
    std::hash<SigmaPrivateKey> hasher;

    key1.Generate();
    key2.Generate();

    BOOST_CHECK_EQUAL(hasher(key1), hasher(key1));
    BOOST_CHECK_NE(hasher(key1), hasher(key2));
}

BOOST_AUTO_TEST_CASE(public_key)
{
    auto& params = DefaultSigmaParams;
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    auto commit = pub.commitment;

    priv.Generate();
    pub.Generate(priv, params);

    BOOST_CHECK(pub.IsValid());
    BOOST_CHECK_NE(pub.commitment, commit);

    // Try a second time to see if we still get the same result.
    commit = pub.commitment;
    pub.Generate(priv, params);

    BOOST_CHECK_EQUAL(pub.commitment, commit);
}

BOOST_AUTO_TEST_CASE(public_key_hash)
{
    auto& params = DefaultSigmaParams;
    SigmaPrivateKey key1, key2;
    std::hash<SigmaPublicKey> hasher;

    key1.Generate();
    key2.Generate();

    BOOST_CHECK_EQUAL(hasher(SigmaPublicKey(key1, params)), hasher(SigmaPublicKey(key1, params)));
    BOOST_CHECK_NE(hasher(SigmaPublicKey(key1, params)), hasher(SigmaPublicKey(key2, params)));
}

BOOST_AUTO_TEST_CASE(proof)
{
    auto& params = DefaultSigmaParams;

    // Create keys.
    SigmaPrivateKey key1, key2, key3;

    key1.Generate();
    key2.Generate();
    key3.Generate();

    // Crete proof.
    SigmaProof proof(params);
    std::vector<SigmaPublicKey> pubs({
        SigmaPublicKey(key1, params),
        SigmaPublicKey(key2, params),
        SigmaPublicKey(key3, params)
    });

    proof.Generate(key2, pubs.begin(), pubs.end(), false);

    BOOST_CHECK_EQUAL(proof.Verify(pubs.begin(), pubs.end(), false), true);
    BOOST_CHECK_EQUAL(proof.Verify(pubs.begin(), pubs.end() - 1, false), false);
}

BOOST_AUTO_TEST_CASE(spend_with_large_anonimity_group)
{
    auto& params = DefaultSigmaParams;
    std::vector<SigmaPublicKey> pubs;

    // 2 ^ 14 coins
    int limit = 1 << 14;

    // generate 2 ^ 14 + 1 coins
    SigmaPrivateKey key;
    for (int i = 0; i < limit + 1; i++) {
        key.Generate();
        pubs.push_back(SigmaPublicKey(key, params));
    }

    SigmaProof validProof(params), invalidProof(params);
    validProof.Generate(key, pubs.begin() + 1, pubs.end(), false); // prove with 2 ^ 14 coins
    invalidProof.Generate(key, pubs.begin(), pubs.end(), false); // prove with 2 ^ 14 + 1 coins

    BOOST_CHECK_EQUAL(validProof.Verify(pubs.begin() + 1, pubs.end(), false), true);
    BOOST_CHECK_EQUAL(invalidProof.Verify(pubs.begin(), pubs.end(), false), false);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
