#ifndef HASH_FUNCTIONS_H__
#define HASH_FUNCTIONS_H__

#include <secp256k1/include/Scalar.h>
#include "sigma/coin.h"

#include <unordered_map>

namespace sigma {

using namespace secp_primitives;

// Custom hash for Scalar values.
struct CScalarHash {
    std::size_t operator()(const Scalar& bn) const noexcept;
};

// Custom hash for the public coin.
struct CPublicCoinHash {
    std::size_t operator()(const sigma::PublicCoin& coin) const noexcept;
};

using spend_info_container = std::unordered_map<Scalar, std::pair<CoinDenomination, int>, sigma::CScalarHash>;

} // namespace sigma

#endif // HASH_FUNCTIONS_H__
