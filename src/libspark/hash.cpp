#include "hash.h"

namespace spark {

using namespace secp_primitives;

// Set up a labeled hash function
Hash::Hash(const std::string label) {
	this->ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(this->ctx, EVP_sha512(), NULL);

	// Write the protocol and mode information
	std::vector<unsigned char> protocol(LABEL_PROTOCOL.begin(), LABEL_PROTOCOL.end());
	EVP_DigestUpdate(this->ctx, protocol.data(), protocol.size());
	EVP_DigestUpdate(this->ctx, &HASH_MODE_FUNCTION, sizeof(HASH_MODE_FUNCTION));

	// Include the label with size
	include_size(label.size());
	std::vector<unsigned char> label_bytes(label.begin(), label.end());
	EVP_DigestUpdate(this->ctx, label_bytes.data(), label_bytes.size());
}

// Clean up
Hash::~Hash() {
	EVP_MD_CTX_free(this->ctx);
}

// Include serialized data in the hash function
void Hash::include(CDataStream& data) {
	include_size(data.size());
	EVP_DigestUpdate(this->ctx, reinterpret_cast<unsigned char *>(data.data()), data.size());
}

// Finalize the hash function to a byte array
std::vector<unsigned char> Hash::finalize() {
    // Use the full output size of the hash function
    std::vector<unsigned char> result;
    result.resize(EVP_MD_size(EVP_sha512()));

    unsigned int TEMP;
    EVP_DigestFinal_ex(this->ctx, result.data(), &TEMP);

    return result;
}

// Finalize the hash function to a scalar
Scalar Hash::finalize_scalar() {
    // Ensure we can properly populate a scalar
    if (EVP_MD_size(EVP_sha512()) < 0 || static_cast<std::size_t>(EVP_MD_size(EVP_sha512())) < SCALAR_ENCODING) {
        throw std::runtime_error("Bad hash size!");
    }

    std::vector<unsigned char> hash;
    hash.resize(EVP_MD_size(EVP_sha512()));
    unsigned char counter = 0;

    EVP_MD_CTX* state_counter;
    state_counter = EVP_MD_CTX_new();
    EVP_DigestInit_ex(state_counter, EVP_sha512(), NULL);

    EVP_MD_CTX* state_finalize;
    state_finalize = EVP_MD_CTX_new();
    EVP_DigestInit_ex(state_finalize, EVP_sha512(), NULL);

    while (1) {
        // Prepare temporary state for counter testing
        EVP_MD_CTX_copy_ex(state_counter, this->ctx);

        // Embed the counter
        EVP_DigestUpdate(state_counter, &counter, sizeof(counter));

        // Finalize the hash with a temporary state
        EVP_MD_CTX_copy_ex(state_finalize, state_counter);
        unsigned int TEMP; // We already know the digest length!
        EVP_DigestFinal_ex(state_finalize, hash.data(), &TEMP);

        // Check for scalar validity
        Scalar candidate;
        try {
            candidate.deserialize(hash.data());

            EVP_MD_CTX_free(state_counter);
            EVP_MD_CTX_free(state_finalize);

            return candidate;
        } catch (const std::exception &) {
            counter++;
        }
    }
}

// Finalize the hash function to a group element
GroupElement Hash::finalize_group() {
	const int GROUP_ENCODING = 34;
	const unsigned char ZERO = 0;

    // Ensure we can properly populate a 
    if (EVP_MD_size(EVP_sha512()) < GROUP_ENCODING) {
        throw std::runtime_error("Bad hash size!");
    }

    std::vector<unsigned char> hash;
    hash.resize(EVP_MD_size(EVP_sha512()));
    unsigned char counter = 0;

    EVP_MD_CTX* state_counter;
    state_counter = EVP_MD_CTX_new();
    EVP_DigestInit_ex(state_counter, EVP_sha512(), NULL);

    EVP_MD_CTX* state_finalize;
    state_finalize = EVP_MD_CTX_new();
    EVP_DigestInit_ex(state_finalize, EVP_sha512(), NULL);

    while (1) {
        // Prepare temporary state for counter testing
        EVP_MD_CTX_copy_ex(state_counter, this->ctx);

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

            EVP_MD_CTX_free(state_counter);
            EVP_MD_CTX_free(state_finalize);

            return candidate;
        } catch (const std::exception &) {
            counter++;
        }
    }
}

// Include a serialized size in the hash function
void Hash::include_size(std::size_t size) {
	CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
	stream << (uint64_t)size;
	EVP_DigestUpdate(this->ctx, reinterpret_cast<unsigned char *>(stream.data()), stream.size());
}

}