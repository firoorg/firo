#ifndef SCALAR_H__
#define SCALAR_H__

#include <stdint.h>
#include <memory>
#include <cstring>
#include <random>
#include "secp256k1.h"
#include "../src/util.h"
#include "../src/scalar.h"

namespace secp_primitives {

// A wrapper over scalar value of Secp library.
class Scalar {
public:

    Scalar();
    // Constructor from interger.
    Scalar(uint64_t value);

    // Constructor from secp object.
    Scalar(const secp256k1_scalar &value);

    // Copy constructor
    Scalar(const Scalar& other);

    Scalar(const char* str);

    // Move constructor
    Scalar(Scalar&& other);

    Scalar& set(const Scalar& other);

    Scalar& operator=(const Scalar& other);

    Scalar& operator=(Scalar&& other) noexcept;

    Scalar& operator=(unsigned int i);

    Scalar& operator=(const unsigned char *bin);

    Scalar operator*(const Scalar& other) const;

    Scalar& operator*=(const Scalar& other);

    Scalar operator+(const Scalar& other) const;

    Scalar& operator+=(const Scalar& other);

    Scalar operator-(const Scalar& other) const;

    Scalar& operator-=(const Scalar& other);

    bool operator==(const Scalar& other) const;

    Scalar inverse() const;

    Scalar negate() const;

    Scalar square() const;

    Scalar exponent(const Scalar& exp) const;
    Scalar exponent(uint64_t exponent) const;

    Scalar& randomize();

    Scalar& generate(unsigned char* buff);

    Scalar& mod_p();

    Scalar hash(const unsigned char* data,size_t len);

    bool isMember() const;

    // Returns the secp object inside it.
    const secp256k1_scalar& get_value() const;

    friend std::ostream& operator<< ( std::ostream& os, const Scalar& c) {
        os << c.tostring();
    return os;
    }

    std::string tostring() const;

    size_t memoryRequired() const;

    unsigned char* serialize(unsigned char* buffer) const;
    unsigned char* deserialize(unsigned char* buffer);

    void get_bits(std::vector<bool>& bits) const;

private:
    std::unique_ptr <secp256k1_scalar> value_;

};

} // namespace secp_primitives

#endif // SCALAR_H__
