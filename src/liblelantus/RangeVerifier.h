#ifndef ZCOIN_RANGEVERIFIER_H
#define ZCOIN_RANGEVERIFIER_H

#include "InnerProductProofVerifier.h"

namespace lelantus {

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
    bool membership_checks(const RangeProof<Exponent, GroupElement>& proof);

private:
    GroupElement g;
    GroupElement h1;
    GroupElement h2;
    const std::vector<GroupElement>& g_;
    const std::vector<GroupElement>& h_;
    uint64_t n;
};

}//namespace lelantus

#include "RangeVerifier.hpp"

#endif //ZCOIN_RANGEVERIFIER_H
