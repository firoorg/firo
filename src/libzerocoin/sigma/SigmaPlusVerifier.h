#ifndef ZCOIN_SIGMAPLUSVERIFIER_H
#define ZCOIN_SIGMAPLUSVERIFIER_H

#include "R1ProofVerifier.h"

namespace sigma {
template<class Exponent, class GroupElement>
class SigmaPlusVerifier{

public:
    SigmaPlusVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens);

    bool verify(const std::vector<GroupElement>& commits,const SigmaPlusProof<Exponent, GroupElement>& proof) const;

private:
    GroupElement g_;
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_;
};

} // namespace sigma

#include "SigmaPlusVerifier.hpp"

#endif //ZCOIN_SIGMAPLUSVERIFIER_H
