#ifndef ZCOIN_UTILS_H
#define ZCOIN_UTILS_H
#include <vector>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <common/GeneratorVector.h>
#include "SigmaPlusProof.h"
#include "NextGenProof.h"
#include "SchnorrProof.h"
#include <algorithm>

namespace nextgen {
template<class Exponent, class GroupElement>
class NextGenPrimitives {

public:
    static void commit(const GroupElement& g,
            const zcoin_common::GeneratorVector<Exponent, GroupElement>& h,
            const std::vector<Exponent>& exp,
            const Exponent& r,
            GroupElement& result_out);

    static GroupElement commit(const GroupElement& g, const Exponent& m, const GroupElement& h, const Exponent& r);

    static GroupElement double_commit(const GroupElement& g, const Exponent& m, const GroupElement& hV, const Exponent& v, const GroupElement& hR, const Exponent& r);

    static void convert_to_sigma(uint64_t num, uint64_t n, uint64_t m, std::vector<Exponent>& out);

    static std::vector<uint64_t> convert_to_nal(uint64_t num, uint64_t n, uint64_t m);

    static void get_x(const GroupElement& A, const GroupElement& C, const GroupElement& D, Exponent& result_out);

    static void get_x(const std::vector<SigmaPlusProof<Exponent, GroupElement>>& proofs, Exponent& result_out);

    static void new_factor(Exponent x, Exponent a, std::vector<Exponent>& coefficients);

    static void get_c(const GroupElement& u, Exponent& result);
    };

}// namespace nextgen

#include "NextGenPrimitives.hpp"

#endif //ZCOIN_UTILS_H
