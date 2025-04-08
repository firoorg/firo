// A design for address scrambling based on `f4jumble`: https://zips.z.cash/zip-0316#jumbling
// This design differs from `f4jumble` to account for limitations on SHA512
// These limitations are unfortunate, but such is life sometimes
//
// To account for these limitations, we do the following:
// - Place extra restrictions on length to avoid XOF input encoding (and because we don't need it)
// - Replace personalization with fixed-length inputs; note that length is NOT prepended
// - Truncate outputs to the proper length
//
// Additionally, we account for the number of rounds by limiting the round counter encoding

#include "f4grumble.h"

namespace spark {

using namespace secp_primitives;

// Compute the XOR of two byte vectors
std::vector<unsigned char> F4Grumble::vec_xor(const std::vector<unsigned char>& x, const std::vector<unsigned char>& y) {
    if (x.size() != y.size()) {
        throw std::invalid_argument("Mismatched vector sizes");
    }

    std::vector<unsigned char> result;
    result.reserve(x.size());
    for (std::size_t i = 0; i < x.size(); i++) {
        result.emplace_back(x[i] ^ y[i]);
    }

    return result;
}

// Return the maximum allowed input size in bytes
std::size_t F4Grumble::get_max_size() {
    return 2 * EVP_MD_size(EVP_sha512());
}

// Instantiate with a given network identifier and expected input length
F4Grumble::F4Grumble(const unsigned char network, const int l_M) {
    // Assert the length is valid
    if (l_M > 2 * EVP_MD_size(EVP_sha512())) {
        throw std::invalid_argument("Bad address size");
    }

    this->network = network;
    this->l_M = l_M;
    this->l_L = l_M / 2;
    this->l_R = l_M - l_L;
}

// Encode the input data
std::vector<unsigned char> F4Grumble::encode(const std::vector<unsigned char>& input) {
    // Check the input size
    if (l_M < 0 || input.size() != static_cast<std::size_t>(l_M)) {
        throw std::invalid_argument("Bad address size");
    }

    // Split the input
    std::vector<unsigned char> a = std::vector<unsigned char>(input.begin(), input.begin() + this->l_M / 2);
    std::vector<unsigned char> b = std::vector<unsigned char>(input.begin() + this->l_M / 2, input.end());

    // Perform the Feistel operations
    std::vector<unsigned char> x = vec_xor(b, G(0, a));
    std::vector<unsigned char> y = vec_xor(a, H(0, x));
    std::vector<unsigned char> d = vec_xor(x, G(1, y));
    std::vector<unsigned char> c = vec_xor(y, H(1, d));

    // Return the concatenation
    std::vector<unsigned char> result(c);
    result.insert(result.end(), d.begin(), d.end());
    return result;
}

// Decode the input data
std::vector<unsigned char> F4Grumble::decode(const std::vector<unsigned char>& input) {
    // Check the input size
    if (l_M < 0 || input.size() != static_cast<std::size_t>(l_M)) {
        throw std::invalid_argument("Bad address size");
    }

    // Split the input
    std::vector<unsigned char> c = std::vector<unsigned char>(input.begin(), input.begin() + this->l_M / 2);
    std::vector<unsigned char> d = std::vector<unsigned char>(input.begin() + this->l_M / 2, input.end());

    // Perform the Feistel operations
    std::vector<unsigned char> y = vec_xor(c, H(1, d));
    std::vector<unsigned char> x = vec_xor(d, G(1, y));
    std::vector<unsigned char> a = vec_xor(y, H(0, x));
    std::vector<unsigned char> b = vec_xor(x, G(0, a));

    // Return the concatenation
    std::vector<unsigned char> result(a);
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

// Feistel round functions
std::vector<unsigned char> F4Grumble::G(const unsigned char i, const std::vector<unsigned char>& u) {
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);

    // Bind the domain separator and network
    std::vector<unsigned char> domain(LABEL_F4GRUMBLE_G.begin(), LABEL_F4GRUMBLE_G.end());
    EVP_DigestUpdate(ctx, domain.data(), domain.size());
    EVP_DigestUpdate(ctx, &this->network, sizeof(this->network));

    // Include the round index
    EVP_DigestUpdate(ctx, &i, sizeof(i));

    // Include the input data
    EVP_DigestUpdate(ctx, u.data(), u.size());

    // Finalize the hash and resize
    std::vector<unsigned char> result;
    result.resize(EVP_MD_size(EVP_sha512()));

    unsigned int TEMP;
    EVP_DigestFinal_ex(ctx, result.data(), &TEMP);
    EVP_MD_CTX_free(ctx);
    result.resize(this->l_R);

    return result;
}

std::vector<unsigned char> F4Grumble::H(const unsigned char i, const std::vector<unsigned char>& u) {
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);

    // Bind the domain separator and network
    std::vector<unsigned char> domain(LABEL_F4GRUMBLE_H.begin(), LABEL_F4GRUMBLE_H.end());
    EVP_DigestUpdate(ctx, domain.data(), domain.size());
    EVP_DigestUpdate(ctx, &this->network, sizeof(this->network));

    // Include the round index
    EVP_DigestUpdate(ctx, &i, sizeof(i));

    // Include the input data
    EVP_DigestUpdate(ctx, u.data(), u.size());

    // Finalize the hash and resize
    std::vector<unsigned char> result;
    result.resize(EVP_MD_size(EVP_sha512()));

    unsigned int TEMP;
    EVP_DigestFinal_ex(ctx, result.data(), &TEMP);
    EVP_MD_CTX_free(ctx);
    result.resize(this->l_L);

    return result;
}

}
