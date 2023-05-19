#include "../aead.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_aead_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(complete)
{
    // Key
    std::string key_string = "Key prefix";
    std::vector<unsigned char> key(key_string.begin(), key_string.end());
    key.resize(AEAD_KEY_SIZE);

    // Serialize
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;

    // Encrypt
    AEADEncryptedData data = AEAD::encrypt(key, "Associated data", ser);

    // Decrypt
    ser = AEAD::decrypt_and_verify(key, "Associated data", data);

    // Deserialize
    int message_;
    ser >> message_;

    BOOST_CHECK_EQUAL(message_, message);
}

BOOST_AUTO_TEST_CASE(bad_tag)
{
    // Key
    std::string key_string = "Key prefix";
    std::vector<unsigned char> key(key_string.begin(), key_string.end());
    key.resize(AEAD_KEY_SIZE);

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(key, "Associated data", ser);

    // Serialize and encrypt an evil message
    ser.clear();
    int evil_message = 666;
    ser << evil_message;
    AEADEncryptedData evil_data = AEAD::encrypt(key, "Associated data", ser);

    // Replace tag
    data.tag = evil_data.tag;

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(key, "Associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bad_ciphertext)
{
    // Key
    std::string key_string = "Key prefix";
    std::vector<unsigned char> key(key_string.begin(), key_string.end());
    key.resize(AEAD_KEY_SIZE);

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(key, "Associated data", ser);

    // Serialize and encrypt an evil message
    ser.clear();
    int evil_message = 666;
    ser << evil_message;
    AEADEncryptedData evil_data = AEAD::encrypt(key, "Associated data", ser);

    // Replace ciphertext
    data.ciphertext = evil_data.ciphertext;

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(key, "Associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bad_associated_data)
{
    // Key
    std::string key_string = "Key prefix";
    std::vector<unsigned char> key(key_string.begin(), key_string.end());
    key.resize(AEAD_KEY_SIZE);

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(key, "Associated data", ser);

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(key, "Evil associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bad_key)
{
    // Key
    std::string key_string = "Key prefix";
    std::vector<unsigned char> key(key_string.begin(), key_string.end());
    key.resize(AEAD_KEY_SIZE);

    // Evil key
    std::string evil_key_string = "Evil key prefix";
    std::vector<unsigned char> evil_key(evil_key_string.begin(), evil_key_string.end());
    evil_key.resize(AEAD_KEY_SIZE);

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(key, "Associated data", ser);

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(evil_key, "Associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

}