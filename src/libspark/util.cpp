#include "util.h"

namespace spark {

using namespace secp_primitives;

// Encrypt a diversifier using AES-256
std::vector<unsigned char> SparkUtils::diversifier_encrypt(const std::vector<unsigned char>& key, const uint64_t i) {
    // Serialize the diversifier
    CDataStream i_stream(SER_NETWORK, PROTOCOL_VERSION);
    i_stream << i;

    // Assert proper sizes
    if (key.size() != AES256_KEYSIZE) {
        throw std::invalid_argument("Bad diversifier encryption key size");
    }

    // Encrypt using padded AES-256 (CBC) using a zero IV
    std::vector<unsigned char> ciphertext;
    ciphertext.resize(AES_BLOCKSIZE);
    std::vector<unsigned char> iv;
    iv.resize(AES_BLOCKSIZE);

    AES256CBCEncrypt aes(key.data(), iv.data(), true);
    aes.Encrypt(reinterpret_cast<unsigned char *>(i_stream.data()), i_stream.size(), ciphertext.data());

    return ciphertext;
}

// Decrypt a diversifier using AES-256
uint64_t SparkUtils::diversifier_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& d) {
    // Assert proper sizes
    if (key.size() != AES256_KEYSIZE) {
        throw std::invalid_argument("Bad diversifier decryption key size");
    }

    // Decrypt using padded AES-256 (CBC) using a zero IV
    CDataStream i_stream(SER_NETWORK, PROTOCOL_VERSION);
    i_stream.resize(sizeof(uint64_t));

    std::vector<unsigned char> iv;
    iv.resize(AES_BLOCKSIZE);

    AES256CBCDecrypt aes(key.data(), iv.data(), true);
    aes.Decrypt(d.data(), d.size(), reinterpret_cast<unsigned char *>(i_stream.data()));

    // Deserialize the diversifier
    uint64_t i;
    i_stream >> i;

    return i;
}

// Produce a uniformly-sampled group element from a label
GroupElement SparkUtils::hash_generator(const std::string label) {
	const int GROUP_ENCODING = 34;
	const unsigned char ZERO = 0;

    // Ensure we can properly populate a 
    if (EVP_MD_size(EVP_blake2b512()) < GROUP_ENCODING) {
        throw std::runtime_error("Bad hash size!");
    }

    EVP_MD_CTX* ctx;
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_blake2b512(), NULL);

    // Write the protocol and mode
    std::vector<unsigned char> protocol(LABEL_PROTOCOL.begin(), LABEL_PROTOCOL.end());
    EVP_DigestUpdate(ctx, protocol.data(), protocol.size());
    EVP_DigestUpdate(ctx, &HASH_MODE_GROUP_GENERATOR, sizeof(HASH_MODE_GROUP_GENERATOR));

    // Write the label
    std::vector<unsigned char> bytes(label.begin(), label.end());
    EVP_DigestUpdate(ctx, bytes.data(), bytes.size());

    std::vector<unsigned char> hash;
    hash.resize(EVP_MD_size(EVP_blake2b512()));
    unsigned char counter = 0;

    EVP_MD_CTX* state_counter;
    state_counter = EVP_MD_CTX_new();
    EVP_DigestInit_ex(state_counter, EVP_blake2b512(), NULL);

    EVP_MD_CTX* state_finalize;
    state_finalize = EVP_MD_CTX_new();
    EVP_DigestInit_ex(state_finalize, EVP_blake2b512(), NULL);

    // Finalize the hash
    while (1) {
        // Prepare temporary state for counter testing
        EVP_MD_CTX_copy_ex(state_counter, ctx);

        // Embed the counter
        EVP_DigestUpdate(state_counter, &counter, sizeof(counter));

        // Finalize the hash with a temporary state
        EVP_MD_CTX_copy_ex(state_finalize, state_counter);
        unsigned int TEMP; // We already know the digest length!
        EVP_DigestFinal_ex(state_finalize, hash.data(), &TEMP);

        // Assemble the serialized input:
		//	bytes 0..31: x coordinate
		//	byte 32: even/odd
		//	byte 33: zero (this point is not infinity)
		unsigned char candidate_bytes[GROUP_ENCODING];
		memcpy(candidate_bytes, hash.data(), 33);
		memcpy(candidate_bytes + 33, &ZERO, 1);
        GroupElement candidate;
        try {
            candidate.deserialize(candidate_bytes);

            // Deserialization can succeed even with an invalid result
            if (!candidate.isMember()) {
                counter++;
                continue;
            }

            EVP_MD_CTX_free(ctx);
            EVP_MD_CTX_free(state_counter);
            EVP_MD_CTX_free(state_finalize);

            return candidate;
        } catch (...) {
            counter++;
        }
    }
}

// Derive an AES key for diversifier encryption/decryption
std::vector<unsigned char> SparkUtils::kdf_diversifier(const Scalar& s1) {
    KDF kdf(LABEL_KDF_DIVERSIFIER);
    
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << s1;
    kdf.include(stream);

    return kdf.finalize(AES256_KEYSIZE);
}

// Derive a ChaCha20 key for AEAD operations
std::vector<unsigned char> SparkUtils::kdf_aead(const GroupElement& K_der) {
    KDF kdf(LABEL_KDF_AEAD);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << K_der;
    kdf.include(stream);

    return kdf.finalize(AEAD_KEY_SIZE);
}

// Hash-to-group function H_div
GroupElement SparkUtils::hash_div(const std::vector<unsigned char>& d) {
    Hash hash(LABEL_HASH_DIV);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << d;
    hash.include(stream);

    return hash.finalize_group();
}

// Hash-to-scalar function H_Q2
Scalar SparkUtils::hash_Q2(const Scalar& s1, const Scalar& i) {
    Hash hash(LABEL_HASH_Q2);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << s1;
    stream << i;
    hash.include(stream);

    return hash.finalize_scalar();
}

// Hash-to-scalar function H_k
Scalar SparkUtils::hash_k(const Scalar& k) {
    Hash hash(LABEL_HASH_K);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << k;
    hash.include(stream);

    return hash.finalize_scalar();
}

// Hash-to-scalar function H_ser
Scalar SparkUtils::hash_ser(const Scalar& k, const std::vector<unsigned char>& serial_context) {
    Hash hash(LABEL_HASH_SER);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << k;
    stream << serial_context;
    hash.include(stream);

    return hash.finalize_scalar();
}

// Hash-to-scalar function H_val
Scalar SparkUtils::hash_val(const Scalar& k) {
    Hash hash(LABEL_HASH_VAL);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << k;
    hash.include(stream);

    return hash.finalize_scalar();
}

// Hash-to-scalar function H_ser1
Scalar SparkUtils::hash_ser1(const Scalar& s, const GroupElement& D) {
    Hash hash(LABEL_HASH_SER1);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << s;
    stream << D;
    hash.include(stream);

    return hash.finalize_scalar();
}

// Hash-to-scalar function H_val1
Scalar SparkUtils::hash_val1(const Scalar& s, const GroupElement& D) {
    Hash hash(LABEL_HASH_VAL1);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << s;
    stream << D;
    hash.include(stream);

    return hash.finalize_scalar();
}

}
