#ifndef ZCOIN_SIGMAPLUSPROVER_H
#define ZCOIN_SIGMAPLUSPROVER_H

#include "SigmaPlusProof.h"
#include "R1ProofGenerator.h"

namespace sigma {

template <class Exponent, class GroupElement>
class SigmaPlusProver{

public:
    SigmaPlusProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens, int n, int m);
    void proof(const std::vector<GroupElement>& commits,
               int l,
               const Exponent& r,
               SigmaPlusProof<Exponent, GroupElement>& proof_out);

private:
    GroupElement g_;
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_;
    int n_;
    int m_;
};

}//namespace sigma

#include "SigmaPlusProver.hpp"

#endif //ZCOIN_SIGMAPLUSPROVER_H
