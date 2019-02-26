#ifndef ZCOIN_INNERP_RODUCT_PROOF_GENERATOR_H
#define ZCOIN_INNERP_RODUCT_PROOF_GENERATOR_H

#include "NextGenPrimitives.h"

namespace nextgen {

template <class Exponent, class GroupElement>
class InnerProductProoveGenerator {

public:
    InnerProductProoveGenerator(
            const zcoin_common::GeneratorVector<Exponent, GroupElement>& g,
            const zcoin_common::GeneratorVector<Exponent, GroupElement>& h,
            const GroupElement& u);

    void generate_proof(
        const std::vector<Exponent>& a,
        const std::vector<Exponent>& b,
        const Exponent& x,
        InnerProductProof<Exponent, GroupElement>& proof_out);

    GroupElement get_P();

private:

    InnerProductProoveGenerator(
            const zcoin_common::GeneratorVector<Exponent, GroupElement>& g,
            const zcoin_common::GeneratorVector<Exponent, GroupElement>& h,
            const GroupElement& u,
            const GroupElement& P);

    void generate_proof_util(
            const std::vector<Exponent>& a,
            const std::vector<Exponent>& b,
            InnerProductProof<Exponent, GroupElement>& proof_out);

    void l(typename std::vector<Exponent>::const_iterator a_start,
           typename std::vector<Exponent>::const_iterator a_end,
           typename std::vector<Exponent>::const_iterator b_start,
           typename std::vector<Exponent>::const_iterator b_end,
           const Exponent& cL,
           GroupElement& result_out);

    void r(typename std::vector<Exponent>::const_iterator a_start,
           typename std::vector<Exponent>::const_iterator a_end,
           typename std::vector<Exponent>::const_iterator b_start,
           typename std::vector<Exponent>::const_iterator b_end,
           const Exponent& cR,
           GroupElement& result_out);

    std::vector<Exponent> a_prime(const Exponent& x, const std::vector<Exponent>& a);

    std::vector<Exponent> b_prime(const Exponent& x, const std::vector<Exponent>& b);

    void compute_P(
            typename std::vector<Exponent>::const_iterator a_start,
            typename std::vector<Exponent>::const_iterator a_end,
            typename std::vector<Exponent>::const_iterator b_start,
            typename std::vector<Exponent>::const_iterator b_end,
            GroupElement& result_out);

private:
    const zcoin_common::GeneratorVector<Exponent, GroupElement>& g_;
    const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_;
    GroupElement u_;
    GroupElement P_;
    GroupElement P_initial;

};

} // namespace nextgen

#include "InnerProductProoveGenerator.hpp"

#endif //ZCOIN_INNERP_RODUCT_PROOF_GENERATOR_H
