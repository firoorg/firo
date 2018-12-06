#ifndef ZCOIN_SIGMAPLUSVERIFIER_H
#define ZCOIN_SIGMAPLUSVERIFIER_H

#include "NextGenPrimitives.h"

namespace nextgen {
template<class Exponent, class GroupElement>
class SigmaPlusVerifier{

public:
    SigmaPlusVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      uint64_t n, uint64_t m_);

    bool verify(const std::vector<GroupElement>& commits,
                const Exponent& x,
                const SigmaPlusProof<Exponent, GroupElement>& proof) const;

    bool verify(const std::vector<GroupElement>& commits,
                const SigmaPlusProof<Exponent, GroupElement>& proof) const;

private:
    GroupElement g_;
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_;
    uint64_t n;
    uint64_t m;
};

} // namespace nextgen

#include "SigmaPlusVerifier.hpp"

#endif //ZCOIN_SIGMAPLUSVERIFIER_H
