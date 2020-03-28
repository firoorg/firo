#ifndef ZCOIN_LIBLELANTUS_INNERP_RODUCT_PROOF_GENERATOR_H
#define ZCOIN_LIBLELANTUS_INNERP_RODUCT_PROOF_GENERATOR_H

#include "lelantus_primitives.h"

namespace lelantus {

template <class Exponent, class GroupElement>
class InnerProductProofGenerator {

public:
    //g and h are being kept by reference, be sure it will not be modified from outside
    InnerProductProofGenerator(
            const std::vector<GroupElement>& g,
            const std::vector<GroupElement>& h,
            const GroupElement& u);

    void generate_proof(
            const std::vector<Exponent>& a,
            const std::vector<Exponent>& b,
            const Exponent& x,
            InnerProductProof<Exponent, GroupElement>& proof_out);

    const GroupElement& get_P();

private:

    InnerProductProofGenerator(
            const std::vector<GroupElement>& g,
            const std::vector<GroupElement>& h,
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
            const std::vector<Exponent>& a,
            const std::vector<Exponent>& b,
            GroupElement& result_out);

private:
    const std::vector<GroupElement>& g_;
    const std::vector<GroupElement>& h_;
    GroupElement u_;
    GroupElement P_;
    GroupElement P_initial;

};

} // namespace lelantus

#include "innerproduct_proof_generator.hpp"

#endif //ZCOIN_LIBLELANTUS_INNERP_RODUCT_PROOF_GENERATOR_H
