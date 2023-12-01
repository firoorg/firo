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

BOOST_AUTO_TEST_CASE(overflow)
{
    // Number of bytes for our diversifier; this needs to exceed `uint64_t` bounds but not the AES block size
    int BYTES = 10;

    // Key
    std::string key_string = "Key prefix";
    std::vector<unsigned char> key(key_string.begin(), key_string.end());
    key.resize(AES256_KEYSIZE);

    // Encrypt a value that will exceed `uint64_t` bounds
    // We have to do this manually since the diversifier API won't let us!
    std::vector<unsigned char> plaintext;
    plaintext.resize(BYTES);
    for (int i = 0; i < BYTES; i++) {
        plaintext[i] = 0xFF; // this will exceed the allowed bounds
    }

    std::vector<unsigned char> ciphertext;
    ciphertext.resize(AES_BLOCKSIZE);
    std::vector<unsigned char> iv;
    iv.resize(AES_BLOCKSIZE);

    AES256CBCEncrypt aes(key.data(), iv.data(), true);
    plaintext.resize(AES_BLOCKSIZE);
    aes.Encrypt(plaintext.data(), BYTES, ciphertext.data());

    // Decrypt
    BOOST_CHECK_THROW(SparkUtils::diversifier_decrypt(key, ciphertext), std::runtime_error);
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

    // Decryption induces a padding failure, so no plaintext is returned
    BOOST_CHECK_THROW(SparkUtils::diversifier_decrypt(evil_key, d), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

}
