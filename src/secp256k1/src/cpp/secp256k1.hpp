#ifndef SECP256K1_CPP_SECP256K1_HPP
#define SECP256K1_CPP_SECP256K1_HPP

#include <secp256k1.hpp>

#include "../secp256k1.h"

namespace secp256k1 {

extern secp256k1_context *default_context;
extern random_bytes_t random_bytes;

} // namespace secp256k1

#endif // SECP256K1_CPP_SECP256K1_HPP
