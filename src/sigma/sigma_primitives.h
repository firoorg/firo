#ifndef ZCOIN_SIGMA_SIGMA_PRIMITIVES_H
#define ZCOIN_SIGMA_SIGMA_PRIMITIVES_H

#include "../secp256k1/include/secp256k1_ecmult.hpp"
#include "../secp256k1/include/secp256k1_scalar.hpp"
#include "../secp256k1/include/secp256k1_group.hpp"

#include <algorithm>
#include <vector>

namespace sigma {

template<class Exponent, class GroupElement>
class SigmaPrimitives {

public:
    static void commit(const GroupElement& g,
            const std::vector<GroupElement>& h,
            const std::vector<Exponent>& exp,
            const Exponent& r,
            GroupElement& result_out);

    static GroupElement commit(const GroupElement& g, const Exponent m, const GroupElement h, const Exponent r);

    static void convert_to_sigma(uint64_t num, uint64_t n, uint64_t m, std::vector<Exponent>& out);

    static std::vector<uint64_t> convert_to_nal(uint64_t num, uint64_t n, uint64_t m);

    static void generate_challenge(const std::vector<GroupElement>& group_elements, 
                                   Exponent& result_out);

    /** \brief Adds a factor of (x*x + a) to the given polynomial in coefficients.
     *  \param[in,out] coefficients Coefficients of the polynomial created.
     */
    static void new_factor(const Exponent& x, const Exponent& a, std::vector<Exponent>& coefficients);

    };

} // namespace sigma

#include "sigma_primitives.hpp"

#endif // ZCOIN_SIGMA_SIGMA_PRIMITIVES_H
