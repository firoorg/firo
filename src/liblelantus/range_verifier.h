#ifndef ZCOIN_LIBLELANTUS_RANGE_VERIFIER_H
#define ZCOIN_LIBLELANTUS_RANGE_VERIFIER_H

#include "innerproduct_proof_verifier.h"

namespace lelantus {

class RangeVerifier {
public:
    //g_vector and h_vector are being kept by reference, be sure it will not be modified from outside
    RangeVerifier(
            const GroupElement& g
            , const GroupElement& h1
            , const GroupElement& h2
            , const std::vector<GroupElement>& g_vector
            , const std::vector<GroupElement>& h_vector
            , uint64_t n);

    bool verify_batch(const std::vector<GroupElement>& V, const RangeProof& proof);

private:
    bool membership_checks(const RangeProof& proof);

private:
    GroupElement g;
    GroupElement h1;
    GroupElement h2;
    const std::vector<GroupElement>& g_;
    const std::vector<GroupElement>& h_;
    uint64_t n;
};

}//namespace lelantus

#endif //ZCOIN_LIBLELANTUS_RANGE_VERIFIER_H
