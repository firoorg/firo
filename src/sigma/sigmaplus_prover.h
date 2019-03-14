#ifndef ZCOIN_SIGMA_SIGMAPLUS_PROVER_H
#define ZCOIN_SIGMA_SIGMAPLUS_PROVER_H

#include "r1_proof_generator.h"
#include "sigmaplus_proof.h"

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

} // namespace sigma

#include "sigmaplus_prover.hpp"

#endif // ZCOIN_SIGMA_SIGMAPLUS_PROVER_H
