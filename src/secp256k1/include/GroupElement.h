#ifndef SECP_GROUP_ELEMENT_H__
#define SECP_GROUP_ELEMENT_H__

#include "Scalar.h"

#include <cstddef>
#include <ostream>
#include <string>
#include <vector>

#include <stddef.h>

namespace secp_primitives {

class GroupElement final {
public:

  GroupElement();

  ~GroupElement();

  GroupElement(const GroupElement& other);

  GroupElement(const char* x,const char* y,  int base = 10);

  GroupElement& set(const GroupElement& other);

  GroupElement& operator=(const GroupElement& other);

  // Operator for multiplying with a scalar number.
  GroupElement operator*(const Scalar& multiplier) const;

  // Operator for multiplying with a scalar number.
  GroupElement& operator*=(const Scalar& multiplier);

  // Operator for adding to another element.
  GroupElement operator+(const GroupElement& other) const;

  // Operator for adding to another element.
  GroupElement& operator+=(const GroupElement& other);

  GroupElement inverse() const;

  void square();

  bool operator==(const GroupElement&other) const;

  bool operator!=(const GroupElement&other) const;

  bool isMember() const;

  GroupElement& generate(unsigned char* seed);

  void sha256(unsigned char* result) const;

  void randomize();

  std::string tostring() const;

  std::string GetHex() const;

  friend std::ostream& operator<< ( std::ostream& os, const GroupElement& s ) {
        os << s.tostring() ;
        return os;
  }

  size_t memoryRequired() const;
  unsigned char* serialize() const;
  unsigned char* serialize(unsigned char* buffer) const;
  unsigned char* deserialize(unsigned char* buffer);

  // These functions are for READWRITE() in serialize.h
  unsigned int GetSerializeSize(int nType=0, int nVersion=0) const
  {
     return memoryRequired();
  }

  template<typename Stream>
  inline void Serialize(Stream& s, int nType, int nVersion) const {
        int size = memoryRequired();
        unsigned char buffer[size];
        serialize(buffer);
        char* b = (char*)buffer;
        s.write(b, size);
  }

  template<typename Stream>
  inline void Unserialize(Stream& s, int nType, int nVersion) {
        int size = memoryRequired();
        unsigned char buffer[size];
        char* b = (char*)buffer;
        s.read(b, size);
        deserialize(buffer);
  }

  //function name like in CBignum
  std::vector<unsigned char> getvch() const;

  std::size_t hash() const;

private:
    GroupElement(const void *g);

private:
    void *g_; // secp256k1_gej

};

} // namespace secp_primitives

namespace std {
    template<>
    struct hash<secp_primitives::GroupElement>
    {
        size_t operator()(const secp_primitives::GroupElement& g) const
        {
            return g.hash();
        }
    };
} // namespace std

#endif // SECP_GROUP_ELEMENT_H__
