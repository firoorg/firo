#include "../sigma.h"

#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace exodus {

BOOST_FIXTURE_TEST_SUITE(exodus_sigma_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(private_key)
{
    SigmaPrivateKey key;

    auto serial = key.GetSerial();
    auto randomness = key.GetRandomness();

    key.Generate();

    BOOST_CHECK(key.IsValid());
    BOOST_CHECK_NE(key.GetSerial(), serial);
    BOOST_CHECK_NE(key.GetRandomness(), randomness);
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
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    auto commit = pub.GetCommitment();

    priv.Generate();
    pub.Generate(priv);

    BOOST_CHECK(pub.IsValid());
    BOOST_CHECK_NE(pub.GetCommitment(), commit);

    // Try a second time to see if we still get the same result.
    commit = pub.GetCommitment();
    pub.Generate(priv);

    BOOST_CHECK_EQUAL(pub.GetCommitment(), commit);
}

BOOST_AUTO_TEST_CASE(public_key_hash)
{
    SigmaPrivateKey key1, key2;
    std::hash<SigmaPublicKey> hasher;

    key1.Generate();
    key2.Generate();

    BOOST_CHECK_EQUAL(hasher(SigmaPublicKey(key1)), hasher(SigmaPublicKey(key1)));
    BOOST_CHECK_NE(hasher(SigmaPublicKey(key1)), hasher(SigmaPublicKey(key2)));
}

BOOST_AUTO_TEST_CASE(proof)
{
    // Create keys.
    SigmaPrivateKey key1, key2, key3;

    key1.Generate();
    key2.Generate();
    key3.Generate();

    // Crete proof.
    SigmaProof proof;
    std::vector<SigmaPublicKey> pubs({
        SigmaPublicKey(key1),
        SigmaPublicKey(key2),
        SigmaPublicKey(key3)
    });

    proof.Generate(key2, pubs.begin(), pubs.end());

    BOOST_CHECK_EQUAL(proof.Verify(sigma::Params::get_default(), pubs.begin(), pubs.end()), true);
    BOOST_CHECK_EQUAL(proof.Verify(sigma::Params::get_default(), pubs.begin(), pubs.end() - 1), false);
}

BOOST_AUTO_TEST_CASE(spend_with_large_anonimity_group)
{
    std::vector<SigmaPublicKey> pubs;

    // 2 ^ 14 coins
    int limit = 1 << 14;

    // generate 2 ^ 14 + 1 coins
    SigmaPrivateKey key;
    for (int i = 0; i < limit + 1; i++) {
        key.Generate();
        pubs.push_back(SigmaPublicKey(key));
    }

    SigmaProof validProof, invalidProof;
    validProof.Generate(key, pubs.begin() + 1, pubs.end()); // prove with 2 ^ 14 coins
    invalidProof.Generate(key, pubs.begin(), pubs.end()); // prove with 2 ^ 14 + 1 coins

    BOOST_CHECK_EQUAL(validProof.Verify(sigma::Params::get_default(), pubs.begin() + 1, pubs.end()), true);
    BOOST_CHECK_EQUAL(invalidProof.Verify(sigma::Params::get_default(), pubs.begin(), pubs.end()), false);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace exodus
