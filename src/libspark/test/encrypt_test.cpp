#include "../util.h"
#include <stdio.h>

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_encrypt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(complete)
{
    // Key
    std::string key_string = "Key prefix";
    std::vector<unsigned char> key(key_string.begin(), key_string.end());
    key.resize(AES256_KEYSIZE);

    // Encrypt
    uint64_t i = 12345;
    std::vector<unsigned char> d = SparkUtils::diversifier_encrypt(key, i);

    // Decrypt
    uint64_t i_ = SparkUtils::diversifier_decrypt(key, d);
    
    BOOST_CHECK_EQUAL(i_, i);
}

BOOST_AUTO_TEST_CASE(bad_key)
{
    // Key
    std::string key_string = "Key prefix";
    std::vector<unsigned char> key(key_string.begin(), key_string.end());
    key.resize(AES256_KEYSIZE);

    // Evil key
    std::string evil_key_string = "Evil key prefix";
    std::vector<unsigned char> evil_key(evil_key_string.begin(), evil_key_string.end());
    evil_key.resize(AES256_KEYSIZE);

    // Encrypt
    uint64_t i = 12345;
    std::vector<unsigned char> d = SparkUtils::diversifier_encrypt(key, i);

    // Decrypt
    uint64_t i_ = SparkUtils::diversifier_decrypt(evil_key, d);
    
    BOOST_CHECK_NE(i_, i);
}

BOOST_AUTO_TEST_SUITE_END()

}
