#include "../keys.h"

#include "../../hash.h"
#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(spark_address_tests, BasicTestingSetup)

// The deterministic derivation of s1 and s2 from r is consensus-critical for
// wallets: changing it changes every wallet's view keys and addresses,
// orphaning previously received funds. These checks pin the deployed
// derivation:
//   s1 = memberFromSeed(SHA256d("s1_generation" || ser(r)))
//   s2 = memberFromSeed(SHA256d("s2_generation"))
// The s2 seed intentionally commits to nothing but its prefix (a historical
// quirk that must be kept for compatibility), so s2 is the same scalar for
// every spend key and must not depend on r or s1.
BOOST_AUTO_TEST_CASE(spend_key_derivation)
{
    const Params* params = Params::get_test();

    Scalar r1, r2;
    r1.randomize();
    r2.randomize();
    const SpendKey key1(params, r1);
    const SpendKey key2(params, r2);

    // Derivation is deterministic in r
    const SpendKey key1_again(params, r1);
    BOOST_CHECK(key1.get_s1() == key1_again.get_s1());
    BOOST_CHECK(key1.get_s2() == key1_again.get_s2());

    // s1 depends on r; s2 does not
    BOOST_CHECK(key1.get_s1() != key2.get_s1());
    BOOST_CHECK(key1.get_s2() == key2.get_s2());

    // s1 matches the pinned derivation
    unsigned char seed[CSHA256::OUTPUT_SIZE];
    std::vector<unsigned char> r_bytes(32);
    r1.serialize(r_bytes.data());
    const std::string prefix1 = "s1_generation";
    CHash256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(prefix1.data()), prefix1.size());
    hasher.Write(r_bytes.data(), r_bytes.size());
    hasher.Finalize(seed);
    Scalar expected_s1;
    expected_s1.memberFromSeed(seed);
    BOOST_CHECK(key1.get_s1() == expected_s1);

    // s2 matches the pinned derivation: the seed hash covers only the prefix
    const std::string prefix2 = "s2_generation";
    hasher.Reset();
    hasher.Write(reinterpret_cast<const unsigned char*>(prefix2.data()), prefix2.size());
    hasher.Finalize(seed);
    Scalar expected_s2;
    expected_s2.memberFromSeed(seed);
    BOOST_CHECK(key1.get_s2() == expected_s2);
}

// Check that correct encoding and decoding succeed
BOOST_AUTO_TEST_CASE(correctness)
{
    // Parameters
    const Params* params;
    params = Params::get_test();

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    Address address(incoming_view_key, i);

    // Encode address
    std::string encoded = address.encode(ADDRESS_NETWORK_TESTNET);

    // Decode address
    Address decoded;
    decoded.decode(encoded);

    // Check correctness
    BOOST_CHECK_EQUAL_COLLECTIONS(address.get_d().begin(), address.get_d().end(), decoded.get_d().begin(), decoded.get_d().end());
    BOOST_CHECK_EQUAL(address.get_Q1(), decoded.get_Q1());
    BOOST_CHECK_EQUAL(address.get_Q2(), decoded.get_Q2());
}

// Check that a bad checksum fails
BOOST_AUTO_TEST_CASE(evil_checksum)
{
    // Parameters
    const Params* params;
    params = Params::get_test();

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    Address address(incoming_view_key, i);

    // Encode address
    std::string encoded = address.encode(ADDRESS_NETWORK_TESTNET);

    // Malleate the checksum
    encoded[encoded.size() - 1] = ~encoded[encoded.size() - 1];

    // Decode address
    Address decoded;
    BOOST_CHECK_THROW(decoded.decode(encoded), std::invalid_argument);
}

// Check that a bad prefix fails
BOOST_AUTO_TEST_CASE(evil_prefix)
{
    // Parameters
    const Params* params;
    params = Params::get_test();

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    Address address(incoming_view_key, i);

    // Encode address
    std::string encoded = address.encode(ADDRESS_NETWORK_TESTNET);

    // Malleate the prefix
    encoded[0] = 'x';

    // Decode address
    Address decoded;
    BOOST_CHECK_THROW(decoded.decode(encoded), std::invalid_argument);
}

// Check that a bad network fails
BOOST_AUTO_TEST_CASE(evil_network)
{
    // Parameters
    const Params* params;
    params = Params::get_test();

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    Address address(incoming_view_key, i);

    // Encode address
    std::string encoded = address.encode(ADDRESS_NETWORK_TESTNET);

    // Malleate the network
    encoded[1] = 'x';

    // Decode address
    Address decoded;
    BOOST_CHECK_THROW(decoded.decode(encoded), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

}
