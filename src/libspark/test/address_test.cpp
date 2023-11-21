#include "../keys.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(spark_address_tests, BasicTestingSetup)

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
