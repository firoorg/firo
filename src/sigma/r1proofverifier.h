#ifndef ZCOIN_R1PROOFVERIFIER_H
#define ZCOIN_R1PROOFVERIFIER_H

namespace sigma {

template <class Exponent, class GroupElement>
class R1ProofVerifier {

public:
    R1ProofVerifier(const GroupElement& g,
            const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_gens,
            const GroupElement& B, int n , int m);

    bool verify(const R1Proof<Exponent, GroupElement>& proof_) const;

    bool verify(const R1Proof<Exponent, GroupElement>& proof_, std::vector<Exponent>& f_) const;

    mutable Exponent x_;

private:
    const GroupElement& g_;
    const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_;
    GroupElement B_Commit;
    int n_, m_;
};

} // namespace sigma

#include "r1proofverifier.hpp"

#endif //ZCOIN_R1PROOFVERIFIER_H
