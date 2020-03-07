#ifndef ZCOIN_LIBLELANTUS_SCHNORR_VERIFIER_H
#define ZCOIN_LIBLELANTUS_SCHNORR_VERIFIER_H

#include "lelantus_primitives.h"

namespace lelantus {

template <class Exponent, class GroupElement>
class SchnorrVerifier {
public:
    SchnorrVerifier(const GroupElement& g, const GroupElement& h);

    bool verify(const GroupElement& y, const SchnorrProof<Exponent, GroupElement>& proof);

private:
    const GroupElement& g_;
    const GroupElement& h_;
};

}//namespace lelantus

#include "schnorr_verifier.hpp"
#endif //ZCOIN_LIBLELANTUS_SCHNORR_VERIFIER_H
