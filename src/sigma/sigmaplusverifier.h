#ifndef ZCOIN_SIGMAPLUSVERIFIER_H
#define ZCOIN_SIGMAPLUSVERIFIER_H

#include "r1proofverifier.h"

namespace sigma {
template<class Exponent, class GroupElement>
class SigmaPlusVerifier{

public:
    SigmaPlusVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      int n, int m_);

    bool verify(const std::vector<GroupElement>& commits,
                const SigmaPlusProof<Exponent, GroupElement>& proof) const;

private:
    GroupElement g_;
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_;
    int n;
    int m;
};

} // namespace sigma

#include "sigmaplusverifier.hpp"

#endif //ZCOIN_SIGMAPLUSVERIFIER_H
