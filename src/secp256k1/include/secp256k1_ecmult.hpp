#ifndef SECP256K1_ECMULT_HPP
#define SECP256K1_ECMULT_HPP

#include <vector>
#include "secp256k1_group.hpp"
#include "secp256k1_scalar.hpp"

namespace secp_primitives {

class MultiExponent {
public:
    MultiExponent(const MultiExponent& other);
    MultiExponent(const std::vector<GroupElement>& generators, const std::vector<Scalar>& powers);
    ~MultiExponent();

    GroupElement get_multiple();

private:
    void  *sc_; // secp256k1_scalar[]
    void  *pt_; // secp256k1_gej[]
    int n_points;
};

}// namespace secp_primitives

#endif //SECP256K1_ECMULT_HPP
