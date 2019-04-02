#ifndef ZCOIN_GENERATORVECTOR_H
#define ZCOIN_GENERATORVECTOR_H

#include <cstddef>
#include <iostream>
#include <vector>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>

namespace zcoin_common {

template <class EXPONENT, class GROUP_ELEMENT>
class GeneratorVector {

public:
    GeneratorVector(const std::vector<GROUP_ELEMENT>& generators, std::size_t precomp = 8);

    /**
     * \param[in] power The power of g which we want to compute.
     * \param[out] result_out The result of computation.
     * \returns g^power in output parameter result_out.
     */
    void get_vector_multiple(
            int range_start,
            int range_end,
            typename std::vector<EXPONENT>::const_iterator power_start,
            typename std::vector<EXPONENT>::const_iterator power_end,
            GROUP_ELEMENT& result_out) const;

    void get_vector_multiple(
            const std::vector<EXPONENT>& powers,
            GROUP_ELEMENT &result_out) const;

    void get_vector_subset_sum(
           const std::vector<bool>& bits, GROUP_ELEMENT &result_out) const;

    const GROUP_ELEMENT& get_g(int i) const;

    int size() const;

private:
    void rec_precompute(
            std::size_t i, std::size_t precomp, std::size_t current_id,
            const GROUP_ELEMENT& current);

private:
    // bit representation of powers
    mutable std::vector<std::vector<bool>> powers_bits;
    std::vector<GROUP_ELEMENT> generators_;
    std::size_t precomp_;
    static const int BIT_LENGTH = 256;
    //precomputing all possible powers for every window
    std::vector<std::vector<GROUP_ELEMENT>> precomp_table_;
};

} // namespace zcoin_common

#include "GeneratorVector.hpp"

#endif //ZCOIN_GENERATORVECTOR_H
