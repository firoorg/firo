#ifndef SECP256K1_CPP_GROUP_HPP
#define SECP256K1_CPP_GROUP_HPP

#include <secp256k1_group.hpp>

#include "secp256k1.hpp"

#include "../group.h"

namespace secp_primitives {

struct GroupElement::Data {
    secp256k1_gej value;

    Data() noexcept;
};

} // namespace secp_primitives

#endif // SECP256K1_CPP_GROUP_HPP