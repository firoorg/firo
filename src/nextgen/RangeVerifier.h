#ifndef ZCOIN_SIGMA_RANGEVERIFIER_H
#define ZCOIN_SIGMA_RANGEVERIFIER_H

#include "InnerProductProofVerifier.h"

namespace nextgen {

template<class Exponent, class GroupElement>
class RangeVerifier {
public:
    RangeVerifier(
              const GroupElement& g
            , const GroupElement& h
            , const std::vector<GroupElement>& g_vector
            , const std::vector<GroupElement>& h_vector
            , uint64_t n);

    bool verify(const GroupElement& V, const RangeProof<Exponent, GroupElement>& proof);
    bool verify_fast(const GroupElement& V, const RangeProof<Exponent, GroupElement>& proof);
    bool verify_optimised(const GroupElement& V, const RangeProof<Exponent, GroupElement>& proof);

private:
    GroupElement g;
    GroupElement h;
    zcoin_common::GeneratorVector<Exponent, GroupElement> g_;
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_;
    uint64_t n;
};

}//namespace nextgen

#include "RangeVerifier.hpp"

#endif //ZCOIN_SIGMA_RANGEVERIFIER_H
