#ifndef FIRO_SPARK_UTIL_H
#define FIRO_SPARK_UTIL_H
#include "../secp256k1/include/Scalar.h"
#include "../secp256k1/include/GroupElement.h"
#include "../crypto/aes.h"
#include "../streams.h"
#include "../version.h"
#include "../util.h"
#include "kdf.h"
#include "hash.h"

namespace spark {

using namespace secp_primitives;

// Useful serialization constant
const std::size_t SCALAR_ENCODING = 32;

// Base protocol separator
const std::string LABEL_PROTOCOL = "SPARK";

// All hash operations have a mode flag to separate their use cases
const unsigned char HASH_MODE_TRANSCRIPT = 0; // a Fiat-Shamir transcript
const unsigned char HASH_MODE_GROUP_GENERATOR = 1; // a prime-order group generator derived from a label
const unsigned char HASH_MODE_FUNCTION = 2; // a hash function derived from a label
const unsigned char HASH_MODE_KDF = 3; // a key derivation function derived from a label

// Transcript labels
const std::string LABEL_TRANSCRIPT_BPPLUS = "BULLETPROOF_PLUS_V1";
const std::string LABEL_TRANSCRIPT_CHAUM = "CHAUM_V1";
const std::string LABEL_TRANSCRIPT_GROOTLE = "GROOTLE_V1";
const std::string LABEL_TRANSCRIPT_SCHNORR = "SCHNORR_V1";
const std::string LABEL_TRANSCRIPT_OWNERSHIP = "OWNERSHIP_V1";

// Generator labels
const std::string LABEL_GENERATOR_F = "F";
const std::string LABEL_GENERATOR_H = "H";
const std::string LABEL_GENERATOR_U = "U";
const std::string LABEL_GENERATOR_G_RANGE = "G_RANGE";
const std::string LABEL_GENERATOR_H_RANGE = "H_RANGE";
const std::string LABEL_GENERATOR_G_GROOTLE = "G_GROOTLE";
const std::string LABEL_GENERATOR_H_GROOTLE = "H_GROOTLE";

// Hash function labels
const std::string LABEL_HASH_DIV = "DIV";
const std::string LABEL_HASH_Q2 = "Q2";
const std::string LABEL_HASH_K = "K";
const std::string LABEL_HASH_SER = "SER";
const std::string LABEL_HASH_VAL = "VAL";
const std::string LABEL_HASH_SER1 = "SER1";
const std::string LABEL_HASH_VAL1 = "VAL1";
const std::string LABEL_HASH_BIND_INNER = "BIND_INNER";
const std::string LABEL_HASH_BIND = "BIND";
const std::string LABEL_F4GRUMBLE_G = "SPARK_F4GRUMBLE_G";
const std::string LABEL_F4GRUMBLE_H = "SPARK_F4GRUMBLE_H";

// KDF labels
const std::string LABEL_KDF_DIVERSIFIER = "DIVERSIFIER";
const std::string LABEL_KDF_AEAD = "AEAD";
const std::string LABEL_COMMIT_AEAD = "COMMIT_AEAD";

// AEAD constants
const int AEAD_IV_SIZE = 12; // byte length of the IV
const int AEAD_KEY_SIZE = 32; // byte length of the key
const int AEAD_TAG_SIZE = 16; // byte length of the tag
const int AEAD_COMMIT_SIZE = 32; // byte length of the key commitment

// Address encoding prefix
const unsigned char ADDRESS_ENCODING_PREFIX = 's';

// Address encoding network identifiers
// TODO: Extend/update/replace these as needed! These are just initial examples
const unsigned char ADDRESS_NETWORK_MAINNET = 'm';
const unsigned char ADDRESS_NETWORK_TESTNET = 't';
const unsigned char ADDRESS_NETWORK_REGTEST = 'r';
const unsigned char ADDRESS_NETWORK_DEVNET =  'd';

class SparkUtils {
public:
    // Protocol-level hash functions
    static GroupElement hash_generator(const std::string label);

    // Hash functions
    static GroupElement hash_div(const std::vector<unsigned char>& d);
    static Scalar hash_Q2(const Scalar& s1, const Scalar& i);
    static Scalar hash_k(const Scalar& k);
    static Scalar hash_ser(const Scalar& k, const std::vector<unsigned char>& serial_context);
    static Scalar hash_val(const Scalar& k);
    static Scalar hash_ser1(const Scalar& s, const GroupElement& D);
    static Scalar hash_val1(const Scalar& s, const GroupElement& D);

    // Key derivation functions
    static std::vector<unsigned char> kdf_diversifier(const Scalar& s1);
    static std::vector<unsigned char> kdf_aead(const GroupElement& K_der);
    static std::vector<unsigned char> commit_aead(const GroupElement& K_der);

    // Diversifier encryption/decryption
    static std::vector<unsigned char> diversifier_encrypt(const std::vector<unsigned char>& key, const uint64_t i);
    static uint64_t diversifier_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& d);
};

}

#endif
