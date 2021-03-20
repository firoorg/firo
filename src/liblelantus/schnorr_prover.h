#ifndef FIRO_LIBLELANTUS_SCHNORR_PROOVER_H
#define FIRO_LIBLELANTUS_SCHNORR_PROOVER_H

#include "lelantus_primitives.h"

namespace lelantus {

class SchnorrProver {
public:
    //g and h are being kept by reference, be sure it will not be modified from outside
    SchnorrProver(const GroupElement& g, const GroupElement& h, bool withFixes_);

    // values a, b and y are included into transcript if(withFixes_), also better to use ChallengeGeneratorHash256 in that case
    void proof(const Scalar& P, const Scalar& T, const GroupElement& y, const GroupElement& a, const GroupElement& b, unique_ptr<ChallengeGenerator>& challengeGenerator, SchnorrProof& proof_out);
    void proof(const Scalar& P, const Scalar& T, const std::vector<GroupElement>& groupElements, SchnorrProof& proof_out);

private:
    const GroupElement& g_;
    const GroupElement& h_;
    bool withFixes;
};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_SCHNORR_PROOVER_H
