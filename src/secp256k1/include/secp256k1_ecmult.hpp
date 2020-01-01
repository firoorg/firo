#ifndef SECP256K1_ECMULT_HPP
#define SECP256K1_ECMULT_HPP

#include "secp256k1_group.hpp"
#include "secp256k1_scalar.hpp"

#include <memory>
#include <vector>

namespace secp_primitives {

class MultiExponent {
public:
    struct Data;

public:
    MultiExponent(const std::vector<GroupElement>& generators, const std::vector<Scalar>& powers);
    MultiExponent(const MultiExponent& other);
    ~MultiExponent();

    MultiExponent& operator=(const MultiExponent& other);

    GroupElement get_multiple();

private:
    std::unique_ptr<Data> data;
};

}// namespace secp_primitives

#endif // SECP256K1_ECMULT_HPP
