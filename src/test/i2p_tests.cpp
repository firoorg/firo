// Copyright (c) 2020-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "i2p.h"
#include "netaddress.h"
#include "netbase.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"

#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(i2p_tests, BasicTestingSetup)

// Test that I2P addresses are correctly parsed via SetSpecial
BOOST_AUTO_TEST_CASE(i2p_address_parsing)
{
    // A valid I2P address (52 character base32 + .b32.i2p suffix)
    // The base32-encoded hash is 52 characters (256 bits / 5 bits per char = 51.2, rounded up)
    CNetAddr addr;
    
    // Test a valid I2P address (52 chars base32 without padding)
    // This is a randomly generated I2P address for testing
    const std::string valid_i2p = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p";
    BOOST_CHECK(addr.SetSpecial(valid_i2p));
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(!addr.IsRoutable()); // I2P addresses are routable within I2P network but IsRoutable() returns false for privacy nets
    BOOST_CHECK_EQUAL(addr.GetNetwork(), NET_I2P);
    
    // The string representation should be the .b32.i2p address
    BOOST_CHECK_EQUAL(addr.ToStringIP(), valid_i2p);
}

BOOST_AUTO_TEST_CASE(i2p_address_invalid)
{
    CNetAddr addr;
    
    // Test invalid I2P addresses
    
    // Too short
    BOOST_CHECK(!addr.SetSpecial("short.b32.i2p"));
    
    // Invalid characters in base32 (contains 1 and 0 which are not in base32)
    BOOST_CHECK(!addr.SetSpecial("ukeu3k5oycgaauneqgtnvselmt4yemv0ilkln7jpvamvfx7dnkdq.b32.i2p"));
    
    // Missing suffix
    BOOST_CHECK(!addr.SetSpecial("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq"));
    
    // Wrong suffix
    BOOST_CHECK(!addr.SetSpecial("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.onion"));
}

BOOST_AUTO_TEST_CASE(i2p_network_type)
{
    // Test that NET_I2P is properly identified
    BOOST_CHECK_EQUAL(ParseNetwork("i2p"), NET_I2P);
    BOOST_CHECK_EQUAL(ParseNetwork("I2P"), NET_I2P);
    BOOST_CHECK_EQUAL(GetNetworkName(NET_I2P), "i2p");
}

BOOST_AUTO_TEST_CASE(i2p_address_group)
{
    CNetAddr addr;
    const std::string valid_i2p = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p";
    BOOST_CHECK(addr.SetSpecial(valid_i2p));
    
    std::vector<bool> asmap; // empty asmap
    std::vector<unsigned char> group = addr.GetGroup(asmap);
    
    // I2P addresses should be grouped by their network type plus first 4 bits
    BOOST_CHECK(!group.empty());
    BOOST_CHECK_EQUAL(group[0], NET_I2P);
}

BOOST_AUTO_TEST_CASE(i2p_address_serialization_v1)
{
    // I2P addresses cannot be serialized in ADDRv1 format (they serialize as all-zeros)
    CNetAddr addr;
    const std::string valid_i2p = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p";
    BOOST_CHECK(addr.SetSpecial(valid_i2p));
    
    // In V1 format, I2P addresses are serialized as all-zeros
    BOOST_CHECK(!addr.IsAddrV1Compatible());
}

BOOST_AUTO_TEST_CASE(i2p_address_serialization_v2)
{
    // I2P addresses can be serialized in ADDRv2 format
    CNetAddr addr;
    const std::string valid_i2p = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p";
    BOOST_CHECK(addr.SetSpecial(valid_i2p));
    
    // Serialize and deserialize in V2 format
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    s << addr;
    
    CNetAddr addr2;
    s >> addr2;
    
    BOOST_CHECK(addr2.IsI2P());
    BOOST_CHECK(addr == addr2);
    BOOST_CHECK_EQUAL(addr.ToStringIP(), addr2.ToStringIP());
}

BOOST_AUTO_TEST_CASE(i2p_service)
{
    // Test CService with I2P address
    CNetAddr addr;
    const std::string valid_i2p = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p";
    BOOST_CHECK(addr.SetSpecial(valid_i2p));
    
    // I2P uses port 0 (SAM 3.1 doesn't use ports)
    CService service(addr, 0);
    BOOST_CHECK(service.IsI2P());
    BOOST_CHECK_EQUAL(service.GetPort(), 0);
    
    // The port in I2P is always 0, so testing with non-zero port
    CService service2(addr, 8333);
    BOOST_CHECK_EQUAL(service2.GetPort(), 8333);
}

BOOST_AUTO_TEST_CASE(i2p_reachability)
{
    CNetAddr addr;
    const std::string valid_i2p = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p";
    BOOST_CHECK(addr.SetSpecial(valid_i2p));
    
    // For I2P addresses, reachability from other I2P addresses should be REACH_PRIVATE
    // This is the highest reachability level for privacy networks
    CNetAddr addr2;
    BOOST_CHECK(addr2.SetSpecial("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaq.b32.i2p"));
    
    // I2P to I2P should have good reachability (REACH_PRIVATE = 5)
    int reachability = addr.GetReachabilityFrom(&addr2);
    BOOST_CHECK(reachability > 0);
}

BOOST_AUTO_TEST_SUITE_END()
