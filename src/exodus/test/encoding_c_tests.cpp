#include "exodus/encoding.h"

#include "exodus/script.h"

#include "script/script.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

// Is resetted to a norm value in each test
extern unsigned nMaxDatacarrierBytes;

BOOST_FIXTURE_TEST_SUITE(exodus_encoding_c_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(class_c_marker)
{
    // Store initial data carrier size
    unsigned nMaxDatacarrierBytesOriginal = nMaxDatacarrierBytes;

    nMaxDatacarrierBytes = 40; // byte

    std::vector<unsigned char> vchMarker;
    vchMarker.push_back(0x65); // "e"
    vchMarker.push_back(0x78); // "x"
    vchMarker.push_back(0x6f); // "o"
    vchMarker.push_back(0x64); // "d"
    vchMarker.push_back(0x75); // "u"
    vchMarker.push_back(0x73); // "s"

    std::vector<unsigned char> vchPayload = ParseHex(
        "00000000000000010000000006dac2c0");

    auto scriptData = EncodeClassC(vchPayload.begin(), vchPayload.end()).scriptPubKey;

    std::vector<std::string> vstrEmbeddedData;
    BOOST_CHECK(GetScriptPushes(scriptData, vstrEmbeddedData));

    BOOST_CHECK_EQUAL(vstrEmbeddedData.size(), 1);
    std::string strEmbeddedData = vstrEmbeddedData.front();
    std::vector<unsigned char> vchEmbeddedData = ParseHex(strEmbeddedData);

    // The embedded data has a size of the payload plus marker
    BOOST_CHECK_EQUAL(
            vchEmbeddedData.size(),
            vchMarker.size() + vchPayload.size());

    // The output script really starts with the marker
    for (size_t n = 0; n < vchMarker.size(); ++n) {
        BOOST_CHECK_EQUAL(vchMarker[n], vchEmbeddedData[n]);
    }

    // The output script really ends with the payload
    std::vector<unsigned char> vchEmbeddedPayload(
        vchEmbeddedData.begin() + vchMarker.size(),
        vchEmbeddedData.end());

    BOOST_CHECK_EQUAL(HexStr(vchEmbeddedPayload), HexStr(vchPayload));

    // Restore original data carrier size settings
    nMaxDatacarrierBytes = nMaxDatacarrierBytesOriginal;
}

BOOST_AUTO_TEST_CASE(class_c_with_empty_payload)
{
    // Store initial data carrier size
    unsigned nMaxDatacarrierBytesOriginal = nMaxDatacarrierBytes;

    const std::vector<unsigned char> vchEmptyPayload;

    // Even less than the size of the marker
    nMaxDatacarrierBytes = 0; // byte

    BOOST_CHECK_THROW(EncodeClassC(vchEmptyPayload.begin(), vchEmptyPayload.end()), std::invalid_argument);

    // Exactly the size of the marker
    nMaxDatacarrierBytes = 8; // byte

    BOOST_CHECK_NO_THROW(EncodeClassC(vchEmptyPayload.begin(), vchEmptyPayload.end()));

    // Restore original data carrier size settings
    nMaxDatacarrierBytes = nMaxDatacarrierBytesOriginal;
}


BOOST_AUTO_TEST_SUITE_END()
