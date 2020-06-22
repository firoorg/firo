#ifndef SECP256K1_SCALAR_HPP
#define SECP256K1_SCALAR_HPP

#include <array>
#include <functional>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include <stddef.h>

namespace secp_primitives {

/**
 * A C++ wrapper over scalar value.
 **/
class Scalar final {
public:
    static constexpr size_t serialize_size = 32;

public:
    struct Data;

public:
    Scalar();
    explicit Scalar(unsigned value);
    explicit Scalar(const unsigned char *bin);
    Scalar(const Data& d);
    Scalar(const Scalar& other);
    ~Scalar();

    Scalar& operator=(unsigned v);
    Scalar& operator=(const unsigned char *bin);
    Scalar& operator=(const Scalar& other);

    Scalar operator*(const Scalar& other) const;
    Scalar& operator*=(const Scalar& other);
    Scalar operator+(const Scalar& other) const;
    Scalar& operator+=(const Scalar& other);
    Scalar operator-(const Scalar& other) const;
    Scalar& operator-=(const Scalar& other);

    bool operator==(const Scalar& other) const;
    bool operator!=(const Scalar& other) const;

    const Data& get_data() const { return *data; }
    void get_bits(std::vector<bool>& bits) const;

    bool isMember() const;

    bool isZero() const;

    Scalar& mod_p();
    Scalar inverse() const;
    Scalar negate() const;
    Scalar square() const;
    Scalar exponent(unsigned exp) const;
    Scalar exponent(const Scalar& exp) const;

    void SetHex(const std::string& hex);
    Scalar& generate(const unsigned char *bin);
    Scalar& memberFromSeed(unsigned char *seed);
    Scalar& randomize();

    Scalar hash(const unsigned char *data, size_t len);

    std::string GetHex() const;
    std::string tostring(unsigned base = 10) const;

    size_t memoryRequired() const { return serialize_size; }
    unsigned char * serialize(unsigned char *buffer) const;
    unsigned const char * deserialize(unsigned const char *buffer);

    unsigned GetSerializeSize(int nType = 0, int nVersion = 0) const {
        return memoryRequired();
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        unsigned char buffer[serialize_size];
        serialize(buffer);
        s.write(reinterpret_cast<char *>(buffer), sizeof(buffer));
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        unsigned char buffer[serialize_size];
        s.read(reinterpret_cast<char *>(buffer), sizeof(buffer));
        deserialize(buffer);
    }

private:
    std::unique_ptr<Data> data;
};

} // namespace secp_primitives

namespace std {

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const secp_primitives::Scalar& c) {
    return os << c.tostring();
}

template<>
struct hash<secp_primitives::Scalar> {
    size_t operator()(const secp_primitives::Scalar& s) const {
        array<unsigned char, 32> d;
        s.serialize(d.data());
        return hash<string>()(string(d.begin(), d.end()));
    }
};

} // namespace std

#endif // SECP256K1_SCALAR_HPP
