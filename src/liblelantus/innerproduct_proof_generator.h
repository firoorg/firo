#ifndef FIRO_LIBLELANTUS_INNERP_RODUCT_PROOF_GENERATOR_H
#define FIRO_LIBLELANTUS_INNERP_RODUCT_PROOF_GENERATOR_H

#include "lelantus_primitives.h"
#include "challenge_generator_impl.h"

namespace lelantus {
    
class InnerProductProofGenerator {

public:
    //g and h are being kept by reference, be sure it will not be modified from outside
    InnerProductProofGenerator(
            const std::vector<GroupElement>& g,
            const std::vector<GroupElement>& h,
            const GroupElement& u,
            int version); // if(version >= 2) we should pass CHash256 in generate_proof function

    void generate_proof(
            const std::vector<Scalar>& a,
            const std::vector<Scalar>& b,
            const Scalar& x,
            unique_ptr<ChallengeGenerator>& challengeGenerator,
            InnerProductProof& proof_out);

    const GroupElement& get_P();

private:

    InnerProductProofGenerator(
            const std::vector<GroupElement>& g,
            const std::vector<GroupElement>& h,
            const GroupElement& u,
            const GroupElement& P,
            int version);

    void generate_proof_util(
            const std::vector<Scalar>& a,
            const std::vector<Scalar>& b,
            unique_ptr<ChallengeGenerator>& challengeGenerator,
            InnerProductProof& proof_out);

    void l(typename std::vector<Scalar>::const_iterator a_start,
           typename std::vector<Scalar>::const_iterator a_end,
           typename std::vector<Scalar>::const_iterator b_start,
           typename std::vector<Scalar>::const_iterator b_end,
           const Scalar& cL,
           GroupElement& result_out);

    void r(typename std::vector<Scalar>::const_iterator a_start,
           typename std::vector<Scalar>::const_iterator a_end,
           typename std::vector<Scalar>::const_iterator b_start,
           typename std::vector<Scalar>::const_iterator b_end,
           const Scalar& cR,
           GroupElement& result_out);

    std::vector<Scalar> a_prime(const Scalar& x, const std::vector<Scalar>& a);

    std::vector<Scalar> b_prime(const Scalar& x, const std::vector<Scalar>& b);

    void compute_P(
            const std::vector<Scalar>& a,
            const std::vector<Scalar>& b,
            GroupElement& result_out);

private:
    const std::vector<GroupElement>& g_;
    const std::vector<GroupElement>& h_;
    GroupElement u_;
    GroupElement P_;
    GroupElement P_initial;
    int version_;

};

} // namespace lelantus

#endif //FIRO_LIBLELANTUS_INNERP_RODUCT_PROOF_GENERATOR_H
