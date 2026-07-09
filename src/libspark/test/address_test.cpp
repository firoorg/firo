#include "../keys.h"

#include "../../hash.h"
#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

#include <array>

namespace spark {

using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(spark_address_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(spend_key_from_r)
{
    const Params* params = Params::get_test();

    Scalar r(42);
    SpendKey spend_key(params, r);
    SpendKey same_spend_key(params, r);
    std::array<unsigned char, Scalar::memoryRequired()> data;
    std::array<unsigned char, CHash256::OUTPUT_SIZE> result;

    CHash256 hash256;
    std::string prefix1 = "s1_generation";
    r.serialize(data.data());
    hash256.Write(reinterpret_cast<const unsigned char*>(prefix1.c_str()), prefix1.size());
    hash256.Write(data.data(), data.size());
    hash256.Finalize(result.data());
    Scalar expected_s1;
    expected_s1.memberFromSeed(result.data());

    std::string prefix2 = "s2_generation";
    hash256.Reset();
    hash256.Write(reinterpret_cast<const unsigned char*>(prefix2.c_str()), prefix2.size());
    hash256.Finalize(result.data());
    Scalar expected_s2;
    expected_s2.memberFromSeed(result.data());

    BOOST_CHECK(spend_key == same_spend_key);
    BOOST_CHECK(spend_key.get_r() == r);
    BOOST_CHECK(spend_key.get_s1() == expected_s1);
    BOOST_CHECK(spend_key.get_s2() == expected_s2);
    BOOST_CHECK(spend_key.get_s1().isMember());
    BOOST_CHECK(spend_key.get_s2().isMember());
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
