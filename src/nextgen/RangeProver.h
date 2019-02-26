#ifndef ZCOIN_SIGMA_RANGEPROVER_H
#define ZCOIN_SIGMA_RANGEPROVER_H

#include "InnerProductProoveGenerator.h"

namespace nextgen {

template<class Exponent, class GroupElement>
class RangeProver {
public:
    RangeProver(
              const GroupElement& g
            , const GroupElement& h1
            , const GroupElement& h2
            , const std::vector<GroupElement>& g_vector
            , const std::vector<GroupElement>& h_vector
            , uint64_t n);

    void batch_proof(
              const std::vector<Exponent>& v
            , const std::vector<Exponent>& serialNumbers
            , const std::vector<Exponent>& randomness
            , RangeProof<Exponent, GroupElement>& proof_out);

private:
    GroupElement g;
    GroupElement h1;
    GroupElement h2;
    zcoin_common::GeneratorVector<Exponent, GroupElement> g_;
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_;
    uint64_t n;

};

}//namespace nextgen

#include "RangeProver.hpp"

#endif //ZCOIN_SIGMA_RANGEPROVER_H
