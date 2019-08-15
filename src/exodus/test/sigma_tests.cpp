#include "../sigma.h"

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_AUTO_TEST_SUITE(exodus_sigma_tests)

BOOST_AUTO_TEST_CASE(private_key)
{
    exodus::SigmaPrivateKey key;

    auto serial = key.GetSerial();
    auto randomness = key.GetRandomness();

    key.Generate();

    BOOST_CHECK(key.IsValid());
    BOOST_CHECK_NE(key.GetSerial(), serial);
    BOOST_CHECK_NE(key.GetRandomness(), randomness);
}

BOOST_AUTO_TEST_CASE(public_key)
{
    exodus::SigmaPrivateKey priv;
    exodus::SigmaPublicKey pub;

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

BOOST_AUTO_TEST_CASE(proof)
{
    // Create keys.
    exodus::SigmaPrivateKey key1, key2, key3;

    key1.Generate();
    key2.Generate();
    key3.Generate();

    // Crete proof.
    exodus::SigmaProof proof;
    std::vector<exodus::SigmaPublicKey> pubs({
        exodus::SigmaPublicKey(key1),
        exodus::SigmaPublicKey(key2),
        exodus::SigmaPublicKey(key3)
    });

    proof.Generate(key2, pubs.begin(), pubs.end());

    BOOST_CHECK_EQUAL(proof.Verify(sigma::Params::get_default(), pubs.begin(), pubs.end()), true);
    BOOST_CHECK_EQUAL(proof.Verify(sigma::Params::get_default(), pubs.begin(), pubs.end() - 1), false);
}

BOOST_AUTO_TEST_SUITE_END()
