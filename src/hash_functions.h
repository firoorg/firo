#ifndef HASH_FUNCTIONS_H__
#define HASH_FUNCTIONS_H__

#include <secp256k1/include/Scalar.h>
#include "libzerocoin/sigma/Coin.h"

namespace sigma {

using namespace secp_primitives;

// Custom hash for Scalar values.
struct CScalarHash {
    std::size_t operator()(const Scalar& bn) const noexcept;
};

// Custom hash for the public coin.
struct CPublicCoinHash {
    std::size_t operator()(const PublicCoinV3& coin) const noexcept;
};

} // namespace sigma

#endif // HASH_FUNCTIONS_H__
