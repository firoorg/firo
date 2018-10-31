#ifndef SECP_GROUP_ELEMENT_H__
#define SECP_GROUP_ELEMENT_H__

#include <memory>
#include <cstring>
#include <random>
#include "Scalar.h"
#include "secp256k1.h"
#include "../src/util.h"
#include "../src/group.h"
#include "../src/group_impl.h"
#include "../src/ecmult_impl.h"
#include "../src/ecmult_const_impl.h"
#include "../src/hash.h"
#include "../src/hash_impl.h"
#include "../src/field.h"
#include "../src/field_impl.h"
#include "../src/scalar_impl.h"
#include "../src/scalar.h"

namespace secp_primitives {

class GroupElement {
public:

  GroupElement();

  ~GroupElement();

  GroupElement(const secp256k1_gej& g);

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

  void randomize();

  void randomize(std::mt19937& rand);

  unsigned char* serialize() const;

  std::string tostring() const;

  friend std::ostream& operator<< ( std::ostream& os, const GroupElement& s ) {
        os << s.tostring() ;
        return os;
  }

    size_t writeMemoryRequired() const;
    unsigned char* encode(unsigned char* buffer) const;
    size_t readMemoryRequired(unsigned char* buffer) const;
    unsigned char*  decode(unsigned char* buffer);

private:

	// Converts the value from secp256k1_gej to secp256k1_ge and returns.
	secp256k1_ge to_ge() const;

//	Implements the algorithm from:
//   Indifferentiable Hashing to Barreto-Naehrig Curves
//    Pierre-Alain Fouque and Mehdi Tibouchi
//    Latincrypt 2012
//
   void indifferent_hash(secp256k1_ge* ge, const secp256k1_fe* t);
   static secp256k1_ecmult_context ctx;

private:
  secp256k1_gej g_;

};

} // namespace secp_primitives

#endif // SECP_GROUP_ELEMENT_H__
