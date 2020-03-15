#ifndef ZCOIN_LIBLELANTUS_RANGE_PROVER_H
#define ZCOIN_LIBLELANTUS_RANGE_PROVER_H

#include "innerproduct_proof_generator.h"

namespace lelantus {

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
    std::vector<GroupElement> g_;
    std::vector<GroupElement> h_;
    uint64_t n;

};

}//namespace lelantus

#include "range_prover.hpp"

#endif //ZCOIN_LIBLELANTUS_RANGE_PROVER_H
