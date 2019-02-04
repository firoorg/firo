#ifndef ZCOIN_INNER_PRODUCT_PROOF_VERIFIER_H
#define ZCOIN_INNER_PRODUCT_PROOF_VERIFIER_H

#include "NextGenPrimitives.h"

namespace nextgen {

template <class Exponent, class GroupElement>
class InnerProductProofVerifier {

public:
    InnerProductProofVerifier(
        const zcoin_common::GeneratorVector<Exponent, GroupElement>& g,
        const zcoin_common::GeneratorVector<Exponent, GroupElement>& h,
        const GroupElement& u,
        const GroupElement& P);

    bool verify (const Exponent& x, const InnerProductProof<Exponent, GroupElement>& proof);
    bool verify_fast(uint64_t n, const Exponent& x, const InnerProductProof<Exponent, GroupElement>& proof);

private:
    bool verify_util(
            const InnerProductProof<Exponent, GroupElement>& proof,
            typename std::vector<GroupElement>::const_iterator ltr_l,
            typename std::vector<GroupElement>::const_iterator itr_r);

    bool verify_fast_util( uint64_t n,  const InnerProductProof<Exponent, GroupElement>& proof);

private:
    const zcoin_common::GeneratorVector<Exponent, GroupElement>& g_;
    const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_;
    GroupElement u_;
    GroupElement P_;

};

} // namespace nextgen

#include "InnerProductProofVerifier.hpp"

#endif //ZCOIN_INNER_PRODUCT_PROOF_VERIFIER_H
