#ifndef ZCOIN_SIGMAPROOFGENERATOR_H
#define ZCOIN_SIGMAPROOFGENERATOR_H

#include "r1proof.h"
#include "sigmaprimitives.h"

namespace sigma {

template <class Exponent, class GroupElement>
class R1ProofGenerator{

public:
    R1ProofGenerator(const GroupElement& g,
                     const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_gens,
                     const std::vector<Exponent>& b,
                     const Exponent& r,
                     int n, int m);

    GroupElement get_B() const { return  B_Commit; }

    void proof(R1Proof<Exponent, GroupElement>& proof_out) const;

    void proof(std::vector<Exponent>& a, R1Proof<Exponent, GroupElement>& proof_out) const;

    mutable Exponent x_;

private:
    const GroupElement& g_;
    const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_;
    std::vector<Exponent> b_;
    Exponent r;
    GroupElement B_Commit;
    int n_; int m_;
};

} //namespace sigma

#include "r1proofgenerator.hpp"

#endif //ZCOIN_SIGMAPROOFGENERATOR_H
