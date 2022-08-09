#include "../aead.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_aead_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(complete)
{
    // Key
    GroupElement prekey;
    prekey.randomize();

    // Serialize
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;

    // Encrypt
    AEADEncryptedData data = AEAD::encrypt(prekey, "Associated data", ser);

    // Decrypt
    ser = AEAD::decrypt_and_verify(prekey, "Associated data", data);

    // Deserialize
    int message_;
    ser >> message_;

    BOOST_CHECK_EQUAL(message_, message);
}

BOOST_AUTO_TEST_CASE(bad_tag)
{
    // Key
    GroupElement prekey;
    prekey.randomize();

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(prekey, "Associated data", ser);

    // Serialize and encrypt an evil message
    ser.clear();
    int evil_message = 666;
    ser << evil_message;
    AEADEncryptedData evil_data = AEAD::encrypt(prekey, "Associated data", ser);

    // Replace tag
    data.tag = evil_data.tag;

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(prekey, "Associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bad_ciphertext)
{
    // Key
    GroupElement prekey;
    prekey.randomize();

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(prekey, "Associated data", ser);

    // Serialize and encrypt an evil message
    ser.clear();
    int evil_message = 666;
    ser << evil_message;
    AEADEncryptedData evil_data = AEAD::encrypt(prekey, "Associated data", ser);

    // Replace ciphertext
    data.ciphertext = evil_data.ciphertext;

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(prekey, "Associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bad_associated_data)
{
    // Key
    GroupElement prekey;
    prekey.randomize();

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(prekey, "Associated data", ser);

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(prekey, "Evil associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bad_key)
{
    // Key
    GroupElement prekey;
    prekey.randomize();

    // Evil key
    GroupElement evil_prekey;
    evil_prekey.randomize();

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(prekey, "Associated data", ser);

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(evil_prekey, "Associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bad_key_commitment)
{
    // Key
    GroupElement prekey;
    prekey.randomize();

    // Evil key and key commitment
    GroupElement evil_prekey;
    evil_prekey.randomize();
    std::vector<unsigned char> evil_key_commitment = SparkUtils::commit_aead(evil_prekey);

    // Serialize and encrypt a message
    int message = 12345;
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;
    AEADEncryptedData data = AEAD::encrypt(prekey, "Associated data", ser);

    // Replace key commitment
    data.key_commitment = evil_key_commitment;

    // Decrypt; this should fail
    BOOST_CHECK_THROW(ser = AEAD::decrypt_and_verify(prekey, "Associated data", data), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

}