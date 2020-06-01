#ifndef SCALAR_H__
#define SCALAR_H__

#include <array>
#include <functional>
#include <ostream>
#include <string>
#include <vector>

#include <inttypes.h>
#include <stddef.h>

namespace secp_primitives {

// A wrapper over scalar value of Secp library.
class Scalar final {
public:

    Scalar();
    // Constructor from interger.
    Scalar(uint64_t value);

    // Copy constructor
    Scalar(const Scalar& other);

    Scalar(const unsigned char* str);

    ~Scalar();

    Scalar& set(const Scalar& other);

    Scalar& operator=(const Scalar& other);

    Scalar& operator=(unsigned int i);

    Scalar& operator=(const unsigned char *bin);

    Scalar operator*(const Scalar& other) const;

    Scalar& operator*=(const Scalar& other);

    Scalar operator+(const Scalar& other) const;

    Scalar& operator+=(const Scalar& other);

    Scalar operator-(const Scalar& other) const;

    Scalar& operator-=(const Scalar& other);

    bool operator==(const Scalar& other) const;
    bool operator!=(const Scalar& other) const;

    Scalar inverse() const;

    Scalar negate() const;

    Scalar square() const;

    Scalar exponent(const Scalar& exp) const;
    Scalar exponent(uint64_t exponent) const;

    Scalar& randomize();

    Scalar& memberFromSeed(unsigned char* seed);

    Scalar& generate(unsigned char* buff);

    Scalar& mod_p();

    Scalar hash(const unsigned char* data,size_t len);

    bool isMember() const;

    bool isZero() const;

    // Returns the secp object inside it.
    const void * get_value() const;

    friend std::ostream& operator<< ( std::ostream& os, const Scalar& c) {
        os << c.tostring();
    return os;
    }

    std::string tostring() const;

    static constexpr size_t memoryRequired() { return 32; }

    unsigned char* serialize(unsigned char* buffer) const;
    unsigned const char* deserialize(unsigned const char* buffer);

    std::string GetHex() const;
    void SetHex(const std::string& str);

    // These functions are for READWRITE() in serialize.h

    unsigned int GetSerializeSize(int nType=0, int nVersion=0) const
    {
        return memoryRequired();
    }

    template<typename Stream>
    inline void Serialize(Stream& s, int nType, int nVersion) const {
        constexpr int size = memoryRequired();
        unsigned char buffer[size];
        serialize(buffer);
        char* b = (char*)buffer;
        s.write(b, size);
    }

    template<typename Stream>
    inline void Unserialize(Stream& s, int nType, int nVersion) {
        constexpr int size = memoryRequired();
        unsigned char buffer[size];
        char* b = (char*)buffer;
        s.read(b, size);
        deserialize(buffer);
    }

    void get_bits(std::vector<bool>& bits) const;

private:
    // Constructor from secp object.
    Scalar(const void *value);

private:
    void *value_; // secp256k1_scalar

};

} // namespace secp_primitives

namespace std {

using namespace secp_primitives;

template<>
struct hash<Scalar> {
    size_t operator()(const Scalar& s) const {
        array<unsigned char, 32> d;
        s.serialize(d.data());
        return hash<string>()(string(d.begin(), d.end()));
    }
};

} // namespace std

#endif // SCALAR_H__
