#ifndef FIRO_LIBSPARK_SCHNORR_H
#define FIRO_LIBSPARK_SCHNORR_H

#include "schnorr_proof.h"

namespace spark {

class Schnorr {
public:
    Schnorr(const GroupElement& G);

    void prove(const Scalar& y, const GroupElement& Y, SchnorrProof& proof);
    bool verify(const GroupElement& Y, SchnorrProof& proof);

private:
    Scalar challenge(const GroupElement& Y, const GroupElement& A);
    const GroupElement& G;
};

}

#endif
