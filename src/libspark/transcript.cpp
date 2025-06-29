#include "transcript.h"

namespace spark {

using namespace secp_primitives;

// Flags for transcript operations
const unsigned char FLAG_DOMAIN = 0;
const unsigned char FLAG_DATA = 1;
const unsigned char FLAG_VECTOR = 2;
const unsigned char FLAG_CHALLENGE = 3;

// Initialize a transcript with a domain separator
Transcript::Transcript(const std::string domain) {
    // Prepare the state
    this->ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(this->ctx, EVP_sha512(), NULL);

    // Write the protocol and mode information
    std::vector<unsigned char> protocol(LABEL_PROTOCOL.begin(), LABEL_PROTOCOL.end());
    EVP_DigestUpdate(this->ctx, protocol.data(), protocol.size());
    EVP_DigestUpdate(this->ctx, &HASH_MODE_TRANSCRIPT, sizeof(HASH_MODE_TRANSCRIPT));

    // Domain separator
    include_flag(FLAG_DOMAIN);
    include_label(domain);
}

Transcript::~Transcript() {
    EVP_MD_CTX_free(this->ctx);
}

Transcript& Transcript::operator=(const Transcript& t) {
    if (this == &t) {
        return *this;
    }

    EVP_MD_CTX_copy_ex(this->ctx, t.ctx);

    return *this;
}

// Add a group element
void Transcript::add(const std::string label, const GroupElement& group_element) {
    std::vector<unsigned char> data;
    data.resize(GroupElement::serialize_size);
    group_element.serialize(data.data());

    include_flag(FLAG_DATA);
    include_label(label);
    include_data(data);
}

// Add a vector of group elements
void Transcript::add(const std::string label, const std::vector<GroupElement>& group_elements) {
    include_flag(FLAG_VECTOR);
    size(group_elements.size());
    include_label(label);
    for (std::size_t i = 0; i < group_elements.size(); i++) {
        std::vector<unsigned char> data;
        data.resize(GroupElement::serialize_size);
        group_elements[i].serialize(data.data());
        include_data(data);
    }
}

// Add a scalar
void Transcript::add(const std::string label, const Scalar& scalar) {
    std::vector<unsigned char> data;
    data.resize(SCALAR_ENCODING);
    scalar.serialize(data.data());

    include_flag(FLAG_DATA);
    include_label(label);
    include_data(data);
}

// Add a vector of scalars
void Transcript::add(const std::string label, const std::vector<Scalar>& scalars) {
    include_flag(FLAG_VECTOR);
    size(scalars.size());
    include_label(label);
    for (std::size_t i = 0; i < scalars.size(); i++) {
        std::vector<unsigned char> data;
        data.resize(SCALAR_ENCODING);
        scalars[i].serialize(data.data());
        include_data(data);
    }
}

// Add arbitrary data
void Transcript::add(const std::string label, const std::vector<unsigned char>& data) {
    include_flag(FLAG_DATA);
    include_label(label);
    include_data(data);
}

// Add arbitrary data, such as serialized group elements or scalars
void Transcript::add(const std::string label, const std::vector<std::vector<unsigned char>>& data) {
    include_flag(FLAG_VECTOR);
    size(data.size());
    include_label(label);
    for (std::size_t i = 0; i < data.size(); i++) {
        include_data(data[i]);
    }
}

// Produce a challenge
Scalar Transcript::challenge(const std::string label) {
    // Ensure we can properly populate a scalar
    if (cmp::less(EVP_MD_size(EVP_sha512()), SCALAR_ENCODING)) {
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

    include_flag(FLAG_CHALLENGE);
    include_label(label);

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
            EVP_MD_CTX_copy_ex(this->ctx, state_counter);

            EVP_MD_CTX_free(state_counter);
            EVP_MD_CTX_free(state_finalize);

            return candidate;
        } catch (const std::exception &) {
            counter++;
        }
    }
}

// Encode and include a size
void Transcript::size(const std::size_t size_) {
    Scalar size_scalar(size_);
    std::vector<unsigned char> size_data;
    size_data.resize(SCALAR_ENCODING);
    size_scalar.serialize(size_data.data());
    EVP_DigestUpdate(this->ctx, size_data.data(), size_data.size());
}

// Include a flag
void Transcript::include_flag(const unsigned char flag) {
    EVP_DigestUpdate(this->ctx, &flag, sizeof(flag));
}

// Encode and include a label
void Transcript::include_label(const std::string label) {
    std::vector<unsigned char> bytes(label.begin(), label.end());
    include_data(bytes);
}

// Encode and include data
void Transcript::include_data(const std::vector<unsigned char>& data) {
    // Include size
    size(data.size());

    // Include data
    EVP_DigestUpdate(this->ctx, data.data(), data.size());
}

}
