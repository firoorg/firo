#ifndef ZCOIN_UTILS_H
#define ZCOIN_UTILS_H
#include <vector>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <libzerocoin/common/GeneratorVector.h>
#include <algorithm>

namespace sigma {
template<class Exponent, class GroupElement>
class SigmaPrimitives {

public:
    static void commit(const GroupElement& g,
            const zcoin_common::GeneratorVector<Exponent, GroupElement>& h,
            const std::vector<Exponent>& exp,
            const Exponent& r,
            GroupElement& result_out);

    static GroupElement commit(const GroupElement& g, const Exponent m, const GroupElement h, const Exponent r);

    static void convert_to_sigma(uint64_t num, uint64_t n, uint64_t m, std::vector<Exponent>& out);

    static std::vector<uint64_t> convert_to_nal(uint64_t num, uint64_t n, uint64_t m);

    static void get_x(const GroupElement& A, const GroupElement& C, const GroupElement& D, Exponent& result_out);

    static void new_factor(Exponent x, Exponent a, std::vector<Exponent>& coefficients);

    };

}// namespace sigma

#include "SigmaPrimitives.hpp"

#endif //ZCOIN_UTILS_H
