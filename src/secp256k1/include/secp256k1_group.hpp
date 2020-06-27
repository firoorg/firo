#ifndef SECP256K1_GROUP_HPP
#define SECP256K1_GROUP_HPP

#include "secp256k1_scalar.hpp"

#include <functional>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include <stddef.h>

namespace secp_primitives {

class GroupElement final {
public:
    static constexpr size_t serialize_size = 34;

public:
    struct Data;

public:
  GroupElement();
  ~GroupElement();
  GroupElement(const GroupElement& other);
  GroupElement(const char* x, const char* y, unsigned base = 10);
  GroupElement(const Data& d);
  GroupElement& operator=(const GroupElement& other);

  // Operator for multiplying with a scalar number.
  GroupElement operator*(const Scalar& scalar) const;
  // Operator for multiplying with a scalar number.
  GroupElement& operator*=(const Scalar& scalar);
  // Operator for adding to another element.
  GroupElement operator+(const GroupElement& other) const;

  // Operator for adding to another element.
  GroupElement& operator+=(const GroupElement& other);

  GroupElement inverse() const;
  void square();

  bool operator==(const GroupElement& other) const;

  bool operator!=(const GroupElement& other) const;

  const Data& get_data() const { return *data; }
  size_t hash() const;
  std::vector<unsigned char> getvch() const;
  void sha256(unsigned char *result) const;

  bool isMember() const;

  bool isInfinity() const;



  GroupElement& set_base_g();
  GroupElement& generate(const unsigned char *seed);
  void randomize();

  std::string GetHex() const;
  std::string tostring(unsigned base = 10) const;

  static constexpr size_t memoryRequired() { return serialize_size; }
  unsigned char * serialize() const;
  unsigned char * serialize(unsigned char *buffer) const;
  unsigned const char * deserialize(unsigned const char *buffer);

  unsigned GetSerializeSize(int nType = 0, int nVersion = 0) const { return memoryRequired(); }

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
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const secp_primitives::GroupElement& ge) {
    return os << (ge.tostring());
}

template<>
struct hash<secp_primitives::GroupElement> {
    size_t operator()(const secp_primitives::GroupElement& v) const {
        return v.hash();
    }
};

} // namespace std

#endif // SECP256K1_GROUP_HPP