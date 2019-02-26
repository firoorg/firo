#ifndef ZCOIN__RANGEVERIFIER_H
#define ZCOIN__RANGEVERIFIER_H

#include "InnerProductProofVerifier.h"

namespace nextgen {

template<class Exponent, class GroupElement>
class RangeVerifier {
public:
    RangeVerifier(
              const GroupElement& g
            , const GroupElement& h1
            , const GroupElement& h2
            , const std::vector<GroupElement>& g_vector
            , const std::vector<GroupElement>& h_vector
            , uint64_t n);

    bool verify_batch(const std::vector<GroupElement>& V, const RangeProof<Exponent, GroupElement>& proof);

private:
    bool isValid(const RangeProof<Exponent, GroupElement>& proof);

private:
    GroupElement g;
    GroupElement h1;
    GroupElement h2;
    zcoin_common::GeneratorVector<Exponent, GroupElement> g_;
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_;
    uint64_t n;
};

}//namespace nextgen

#include "RangeVerifier.hpp"

#endif //ZCOIN_SIGMA_RANGEVERIFIER_H
