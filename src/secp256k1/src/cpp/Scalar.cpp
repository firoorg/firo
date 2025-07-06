#include "include/Scalar.h"

#include "include/secp256k1.h"

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "../scalar.h"
#include "../scalar_impl.h"
#include "../hash_impl.h"
#include "../hash.h"

#include <array>
#include <sstream>
#include <iostream>
#include <openssl/rand.h>

namespace secp_primitives {

Scalar::Scalar()
   : value_(new secp256k1_scalar()) {
    secp256k1_scalar_clear(reinterpret_cast<secp256k1_scalar *>(value_));
}

Scalar::Scalar(uint64_t value)
   : value_(new secp256k1_scalar()) {
    unsigned char b32[32];
    for(int i = 0; i < 24; i++)
        b32[i] = 0;
    b32[24] = value >> 56;
    b32[25] = value >> 48;
    b32[26] = value >> 40;
    b32[27] = value >> 32;
    b32[28] = value >> 24;
    b32[29] = value >> 16;
    b32[30] = value >> 8;
    b32[31] = value;
    secp256k1_scalar_set_b32(reinterpret_cast<secp256k1_scalar *>(value_), b32, 0);
}

Scalar::Scalar(const unsigned char* str)
     : value_(new secp256k1_scalar()) {
    secp256k1_scalar_set_b32(reinterpret_cast<secp256k1_scalar *>(value_), str, 0);
}

Scalar::Scalar(const void *value)
   : value_(new secp256k1_scalar(*reinterpret_cast<const secp256k1_scalar *>(value))) {

}

Scalar::Scalar(const Scalar& other)
   : value_(new secp256k1_scalar(*reinterpret_cast<const secp256k1_scalar *>(other.value_))) {

}

Scalar::~Scalar() {
    delete reinterpret_cast<secp256k1_scalar *>(value_);
}

Scalar& Scalar::operator=(const Scalar& other) {
    return set(other);
}

Scalar& Scalar::operator=(unsigned int i) {
    secp256k1_scalar_set_int(reinterpret_cast<secp256k1_scalar *>(value_), i);
    return *this;
}

Scalar& Scalar::operator=(const unsigned char *bin){
    secp256k1_scalar_set_b32(reinterpret_cast<secp256k1_scalar *>(value_), bin, NULL);
    return *this;
}

Scalar& Scalar::set(const Scalar& other) {
    *reinterpret_cast<secp256k1_scalar *>(value_) = *reinterpret_cast<const secp256k1_scalar *>(other.value_);
    return *this;
}

Scalar Scalar::operator*(const Scalar& other) const {
    secp256k1_scalar result;
    secp256k1_scalar_mul(&result, reinterpret_cast<const secp256k1_scalar *>(value_), reinterpret_cast<const secp256k1_scalar *>(other.value_));
    return &result;
}

Scalar& Scalar::operator*=(const Scalar& other) {
    secp256k1_scalar result;

    secp256k1_scalar_mul(&result, reinterpret_cast<const secp256k1_scalar *>(value_), reinterpret_cast<const secp256k1_scalar *>(other.value_));
    *reinterpret_cast<secp256k1_scalar *>(value_) = result;

    return *this;
}

Scalar Scalar::operator+(const Scalar& other) const {
    secp256k1_scalar result;
    secp256k1_scalar_add(&result, reinterpret_cast<const secp256k1_scalar *>(value_), reinterpret_cast<const secp256k1_scalar *>(other.value_));
    return &result;
}

Scalar& Scalar::operator+=(const Scalar& other) {
    secp256k1_scalar result;

    secp256k1_scalar_add(&result, reinterpret_cast<const secp256k1_scalar *>(value_), reinterpret_cast<const secp256k1_scalar *>(other.value_));
    *reinterpret_cast<secp256k1_scalar *>(value_) = result;

    return *this;
}

Scalar Scalar::operator-(const Scalar& other) const {
    secp256k1_scalar negated, result;

    secp256k1_scalar_negate(&negated, reinterpret_cast<const secp256k1_scalar *>(other.value_));
    secp256k1_scalar_add(&result, &negated, reinterpret_cast<const secp256k1_scalar *>(value_));

    return &result;
}

Scalar& Scalar::operator-=(const Scalar& other) {
    secp256k1_scalar negated, result;

    secp256k1_scalar_negate(&negated, reinterpret_cast<const secp256k1_scalar *>(other.value_));
    secp256k1_scalar_add(&result, reinterpret_cast<const secp256k1_scalar *>(value_), &negated);
    *reinterpret_cast<secp256k1_scalar *>(value_) = result;

    return *this;
}

bool Scalar::operator==(const Scalar& other) const {
    return secp256k1_scalar_eq(reinterpret_cast<const secp256k1_scalar *>(value_), reinterpret_cast<const secp256k1_scalar *>(other.value_));
}

bool Scalar::operator!=(const Scalar& other) const {
    return !(secp256k1_scalar_eq(reinterpret_cast<const secp256k1_scalar *>(value_), reinterpret_cast<const secp256k1_scalar *>(other.value_)));
}

const void * Scalar::get_value() const {
    return value_;
}

Scalar Scalar::inverse() const {
    secp256k1_scalar result;
    secp256k1_scalar_inverse(&result, reinterpret_cast<const secp256k1_scalar *>(value_));
 return &result;
}

Scalar Scalar::negate() const {
    secp256k1_scalar result;
    secp256k1_scalar_negate(&result, reinterpret_cast<const secp256k1_scalar *>(value_));
    return &result;
}

Scalar Scalar::square() const{
    secp256k1_scalar result;
    secp256k1_scalar_sqr(&result, reinterpret_cast<const secp256k1_scalar *>(value_));
 return &result;
}

Scalar Scalar::exponent(const Scalar& exp) const {
    secp256k1_scalar value(*reinterpret_cast<const secp256k1_scalar *>(value_));
    secp256k1_scalar exp_(*reinterpret_cast<const secp256k1_scalar *>(exp.value_));
    secp256k1_scalar result;

    secp256k1_scalar_set_int(&result, 1);

    while (!secp256k1_scalar_is_zero(&exp_)) {
        secp256k1_scalar tmp;

        if (!secp256k1_scalar_is_even(&exp_)) {
            secp256k1_scalar_mul(&tmp, &result, &value);
            result = tmp;
        }

        secp256k1_scalar_sqr(&tmp, &value);
        value = tmp;

        secp256k1_scalar_shr_int(&exp_, 1);
    }

    return &result;
}

Scalar Scalar::exponent(uint64_t exp) const {
    Scalar exp_(exp);
    return exponent(exp_);

}

bool Scalar::isMember() const {
    Scalar temp(*this);
    temp.mod_p();
    return *this == temp;
}

bool Scalar::isZero() const {
    return secp256k1_scalar_is_zero(reinterpret_cast<const secp256k1_scalar *>(value_));
}

Scalar& Scalar::memberFromSeed(unsigned char* seed) {
    // buffer -> object
    deserialize(seed);
    do {
        // object -> buffer
        serialize(seed);
        // Hash from buffer, stores result in object
        *this = hash(seed, 32);
    }while (!(this->isMember()));

    return *this;
}

Scalar& Scalar::randomize() {
    unsigned char temp[32] = { 0 };

    do {
        if (RAND_bytes(temp, 32) != 1) {
            throw std::runtime_error("Unable to generate random Scalar");
        }
        generate(temp);
    } while (!this->isMember()); // we need to ensure, generated value is valid

    return *this;
}

Scalar& Scalar::generate(unsigned char* buff) {
    secp256k1_scalar zero, result;

    secp256k1_scalar_set_b32(reinterpret_cast<secp256k1_scalar *>(value_), buff, nullptr);
    secp256k1_scalar_set_int(&zero, 0);

    secp256k1_scalar_add(&result, reinterpret_cast<const secp256k1_scalar *>(value_), &zero);
    *reinterpret_cast<secp256k1_scalar *>(value_) = result;

    return *this;
}

Scalar& Scalar::mod_p() {
    secp256k1_scalar zero, result;

    secp256k1_scalar_clear(&zero);
    secp256k1_scalar_add(&result, reinterpret_cast<const secp256k1_scalar *>(value_), &zero);
    *reinterpret_cast<secp256k1_scalar *>(value_) = result;

    return *this;
}

Scalar Scalar::hash(const unsigned char* data, size_t len) {
    unsigned char hash[32];

    secp256k1_sha256_t sha256;
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, data, len);
    secp256k1_sha256_finalize(&sha256, hash);

    int overflow = 0;
    secp256k1_scalar result;
    secp256k1_scalar_set_b32(&result,hash,&overflow);
    if (overflow) {
     throw std::runtime_error("Scalar: hashing overflowed");
    }
    Scalar result_(&result);
    result_.mod_p();
    return result_;
}

std::size_t Scalar::get_hash() const {
    auto scalar = reinterpret_cast<const secp256k1_scalar *>(value_);
    return scalar->d[0] ^ (scalar->d[1] << 8);
}

std::string Scalar::tostring() const {
    unsigned char buffer[32];
    std::stringstream ss;

    secp256k1_scalar_get_b32(buffer, reinterpret_cast<const secp256k1_scalar *>(value_));

    for (int i = 0; i < 32; ++i) {
        ss << (int)buffer[i];
    }

    return ss.str();
}

unsigned char* Scalar::serialize(unsigned char* buffer) const {
    secp256k1_scalar_get_b32(buffer, reinterpret_cast<const secp256k1_scalar *>(value_));
    return buffer + 32;
}

unsigned const char* Scalar::deserialize(unsigned const char* buffer) {
    int overflow = 0;

    secp256k1_scalar_set_b32(reinterpret_cast<secp256k1_scalar *>(value_), buffer, &overflow);

    if (overflow) {
        throw std::runtime_error("Scalar: decoding overflowed");
    }

    return buffer + 32;
}

std::string Scalar::GetHex() const {
    std::array<unsigned char, 32> buffer;
    secp256k1_scalar_get_b32(buffer.data(), reinterpret_cast<const secp256k1_scalar *>(value_));

    std::stringstream ss;
    ss << std::hex;
    for (const auto b : buffer) {
        ss << (b >> 4);
        ss << (b & 0xF);
    }

    return ss.str();
}

void Scalar::SetHex(const std::string& str) {
    if (str.size() != 64) {
        throw std::runtime_error("Scalar: decoding invalid length");
    }

    std::array<unsigned char, 32> buffer;

    for (std::size_t i = 0; i < buffer.size(); i++) {
        auto hexs = str.substr(2 * i, 2);

        if (::isxdigit(hexs[0]) && ::isxdigit(hexs[1])) {
            buffer[i] = strtol(hexs.c_str(), NULL, 16);
        } else {
            throw std::runtime_error("Scalar: decoding invalid hex");
        }
    }

    int overflow = 0;

    secp256k1_scalar_set_b32(reinterpret_cast<secp256k1_scalar *>(value_), buffer.data(), &overflow);

    if (overflow) {
        throw std::runtime_error("Scalar: decoding overflowed");
    }
}

void Scalar::get_bits(std::vector<bool>& bits) const {
    unsigned char bin[32];

    secp256k1_scalar_get_b32(bin, reinterpret_cast<const secp256k1_scalar *>(value_));

    for (int i = 0; i < 32; ++i) {
        int32_t val = bin[i];
        for (int j = 7; j >= 0; j--) {
            bits.push_back((val >> j) & 1);
        }
    }
}

} // namespace secp_primitives
