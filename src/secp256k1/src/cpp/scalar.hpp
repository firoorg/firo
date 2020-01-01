#ifndef SECP256K1_CPP_SCALAR_HPP
#define SECP256K1_CPP_SCALAR_HPP

#include <secp256k1_scalar.hpp>

#include "secp256k1.hpp"

#include "../scalar.h"

namespace secp_primitives {

struct Scalar::Data {
    secp256k1_scalar value;

    Data() noexcept;
};

} // namespace secp_primitives

#endif // SECP256K1_CPP_SCALAR_HPP
