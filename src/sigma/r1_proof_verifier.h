#ifndef FIRO_SIGMA_R1_PROOF_VERIFIER_H
#define FIRO_SIGMA_R1_PROOF_VERIFIER_H

namespace sigma {

template <class Exponent, class GroupElement>
class R1ProofVerifier {

public:
    R1ProofVerifier(const GroupElement& g,
            const std::vector<GroupElement>& h_gens,
            const GroupElement& B, int n , int m);

    bool verify(const R1Proof<Exponent, GroupElement>& proof,
                bool skip_final_response_verification = false) const;

    bool verify(const R1Proof<Exponent, GroupElement>& proof,
                std::vector<Exponent>& f_out,
                bool skip_final_response_verification = false) const;

    bool verify_final_response(
            const R1Proof<Exponent, GroupElement>& proof,
            const Exponent& challenge_x,
            std::vector<Exponent>& f_out) const;

private:
    const GroupElement& g_;
    const std::vector<GroupElement>& h_;
    GroupElement B_Commit;
    int n_;
    int m_;
};

} // namespace sigma

#include "r1_proof_verifier.hpp"

#endif // FIRO_SIGMA_R1_PROOF_VERIFIER_H
