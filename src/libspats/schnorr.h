#ifndef FIRO_LIBSPARK_SCHNORR_H
#define FIRO_LIBSPARK_SCHNORR_H

#include "schnorr_proof.h"
#include <secp256k1/include/MultiExponent.h>

namespace spark {

class Schnorr {
public:
    Schnorr(const GroupElement& G);

    void prove(const Scalar& y, const GroupElement& Y, SchnorrProof& proof);
    void prove(const std::vector<Scalar>& y, const std::vector<GroupElement>& Y, SchnorrProof& proof);
    bool verify(const GroupElement& Y, const SchnorrProof& proof);
    bool verify(const std::vector<GroupElement>& Y, const SchnorrProof& proof);

private:
    Scalar challenge(const std::vector<GroupElement>& Y, const GroupElement& A);
    const GroupElement& G;
};

}

#endif
