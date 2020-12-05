#ifndef FIRO_LIBLELANTUS_SCHNORR_PROOVER_H
#define FIRO_LIBLELANTUS_SCHNORR_PROOVER_H

#include "lelantus_primitives.h"

namespace lelantus {

class SchnorrProver {
public:
    //g and h are being kept by reference, be sure it will not be modified from outside
    SchnorrProver(const GroupElement& g, const GroupElement& h);

    void proof(const Scalar& P, const Scalar& T, SchnorrProof& proof_out);

private:
    const GroupElement& g_;
    const GroupElement& h_;
};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_SCHNORR_PROOVER_H
