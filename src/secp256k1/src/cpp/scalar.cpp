#include "scalar.hpp"

#include "num.hpp"
#include "secp256k1.hpp"

#include "../hash_impl.h"
#include "../scalar_impl.h"

#include <array>

#include <ctype.h>
#include <stddef.h>
#include <stdexcept>
#include <stdlib.h>

namespace secp_primitives {

Scalar::Data::Data() noexcept {
    secp256k1_scalar_clear(&value);
}

Scalar::Scalar() : data(new Data()) {
}

Scalar::Scalar(unsigned value) : Scalar() {
    secp256k1_scalar_set_int(&data->value, value);
}

Scalar::Scalar(const unsigned char *bin) : Scalar() {
    int overflow;

    secp256k1_scalar_set_b32(&data->value, bin, &overflow);

    if (overflow) {
        throw std::overflow_error("The value is too large");
    }
}

Scalar::Scalar(const Data& d) : data(new Data(d)) {
}

Scalar::Scalar(const Scalar& other) : data(new Data(*other.data)) {
}

Scalar::~Scalar() {
    // don't remove this destructor otherwise it will inlined on the outside and cause linking error due to
    // Scalar::Data is incomplete type
}

Scalar& Scalar::operator=(unsigned v) {
    secp256k1_scalar_set_int(&data->value, v);
    return *this;
}

Scalar& Scalar::operator=(const unsigned char *bin) {
    secp256k1_scalar_set_b32(&data->value, bin, nullptr);
    return *this;
}

Scalar& Scalar::operator=(const Scalar& other) {
    *data = *other.data;
    return *this;
}

Scalar Scalar::operator*(const Scalar& other) const {
    Data d;
    secp256k1_scalar_mul(&d.value, &data->value, &other.data->value);
    return d;
}

Scalar& Scalar::operator*=(const Scalar& other) {
    secp256k1_scalar r;

    secp256k1_scalar_mul(&r, &data->value, &other.data->value);
    data->value = r;

    return *this;
}

Scalar Scalar::operator+(const Scalar& other) const {
    Data d;
    secp256k1_scalar_add(&d.value, &data->value, &other.data->value);
    return d;
}

Scalar& Scalar::operator+=(const Scalar& other) {
    secp256k1_scalar r;

    secp256k1_scalar_add(&r, &data->value, &other.data->value);
    data->value = r;

    return *this;
}

Scalar Scalar::operator-(const Scalar& other) const {
    secp256k1_scalar negated;
    Data d;

    secp256k1_scalar_negate(&negated, &other.data->value);
    secp256k1_scalar_add(&d.value, &data->value, &negated);

    return d;
}

Scalar& Scalar::operator-=(const Scalar& other) {
    secp256k1_scalar negated, result;

    secp256k1_scalar_negate(&negated, &other.data->value);
    secp256k1_scalar_add(&result, &data->value, &negated);

    data->value = result;

    return *this;
}

bool Scalar::operator==(const Scalar& other) const {
    return secp256k1_scalar_eq(&data->value, &other.data->value);
}

bool Scalar::operator!=(const Scalar& other) const {
    return !(*this == other);
}

unsigned char * Scalar::serialize(unsigned char *buffer) const {
    secp256k1_scalar_get_b32(buffer, &data->value);
    return buffer + 32;
}

unsigned const char * Scalar::deserialize(unsigned const char *buffer) {
    int overflow;

    secp256k1_scalar_set_b32(&data->value, buffer, &overflow);

    if (overflow) {
        throw "Scalar: decoding overflowed";
    }

    return buffer + 32;
}

void Scalar::get_bits(std::vector<bool>& bits) const {
    unsigned char bin[32];

    secp256k1_scalar_get_b32(bin, &data->value);

    for (auto b : bin) {
        for (int j = 7; j >= 0; j--) {
            bits.push_back((b >> j) & 1);
        }
    }
}

bool Scalar::isMember() const {
    return *this == Scalar(*this).mod_p();
}

bool Scalar::isZero() const {
    return secp256k1_scalar_is_zero(&data->value);
}

Scalar& Scalar::mod_p() {
    secp256k1_scalar zero, result;

    secp256k1_scalar_clear(&zero);
    secp256k1_scalar_add(&result, &data->value, &zero);

    data->value = result;

    return *this;
}

Scalar Scalar::inverse() const {
    Data d;
    secp256k1_scalar_inverse(&d.value, &data->value);
    return d;
}

Scalar Scalar::negate() const {
    Data d;
    secp256k1_scalar_negate(&d.value, &data->value);
    return d;
}

Scalar Scalar::square() const {
    Data d;
    secp256k1_scalar_sqr(&d.value, &data->value);
    return d;
}

Scalar Scalar::exponent(unsigned exp) const {
    return exponent(Scalar(exp));
}

Scalar Scalar::exponent(const Scalar& exp) const {
    auto value = data->value;
    auto exp_ = exp.data->value;
    Data result;

    secp256k1_scalar_set_int(&result.value, 1);

    while (!secp256k1_scalar_is_zero(&exp_)) {
        secp256k1_scalar tmp;

        if (!secp256k1_scalar_is_even(&exp_)) {
            secp256k1_scalar_mul(&tmp, &result.value, &value);
            result.value = tmp;
        }

        secp256k1_scalar_sqr(&tmp, &value);
        value = tmp;

        secp256k1_scalar_shr_int(&exp_, 1);
    }

    return result;
}

void Scalar::SetHex(const std::string& hex) {
    if (hex.size() != 64) {
        throw "Scalar: decoding invalid length";
    }

    unsigned char buffer[32];
    int overflow;

    for (size_t i = 0; i < 32; i++) {
        auto b = hex.substr(i * 2, 2);

        if (::isxdigit(b[0]) && ::isxdigit(b[1])) {
            buffer[i] = strtol(b.c_str(), nullptr, 16);
        } else {
            throw "Scalar: decoding invalid hex";
        }
    }

    secp256k1_scalar_set_b32(&data->value, buffer, &overflow);

    if (overflow) {
        throw "Scalar: decoding overflowed";
    }
}

Scalar& Scalar::generate(const unsigned char *bin) {
    secp256k1_scalar zero, result;

    secp256k1_scalar_set_b32(&data->value, bin, nullptr);
    secp256k1_scalar_set_int(&zero, 0);

    secp256k1_scalar_add(&result, &data->value, &zero);
    data->value = result;

    return *this;
}

Scalar& Scalar::memberFromSeed(unsigned char *seed) {
    // buffer -> object
    deserialize(seed);

    do {
        // object -> buffer
        serialize(seed);
        // Hash from buffer, stores result in object
        *this = hash(seed, 32);
    } while (!isMember());

    return *this;
}

Scalar& Scalar::randomize() {
    unsigned char seed[32];

    do {
        secp256k1::random_bytes(seed, sizeof(seed));
        generate(seed);
    } while (!isMember());

    return *this;
}

Scalar Scalar::hash(const unsigned char *data, size_t len) {
    secp256k1_sha256 sha256;
    unsigned char hash[32];
    Data result;
    int overflow;

    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, data, len);
    secp256k1_sha256_finalize(&sha256, hash);

    secp256k1_scalar_set_b32(&result.value, hash, &overflow);

    if (overflow) {
        throw "Scalar: hashing overflowed";
    }

    return Scalar(result).mod_p();
}

std::string Scalar::GetHex() const {
    return tostring(16);
}

std::string Scalar::tostring(unsigned base) const {
    std::array<unsigned char, 32> bin;

    secp256k1_scalar_get_b32(bin.data(), &data->value);

    return secp256k1::int_to_string(bin.begin(), bin.end(), base, false);
}

} // namespace secp_primitives