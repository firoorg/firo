#ifndef SECP256K1_CPP_ECMULT_HPP
#define SECP256K1_CPP_ECMULT_HPP

#include <secp256k1_ecmult.hpp>

#include "secp256k1.hpp"

#include "../group.h"
#include "../scalar.h"

#include <vector>

namespace secp_primitives {

struct MultiExponent::Data {
    std::vector<secp256k1_scalar> sc;
    std::vector<secp256k1_gej> pt;
};

} // namespace secp_primitives

#endif // SECP256K1_CPP_ECMULT_HPP