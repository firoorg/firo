#ifndef FIRO_LIBLELANTUS_LELANTUSPROOF_H
#define FIRO_LIBLELANTUS_LELANTUSPROOF_H

#include "sigmaextended_proof.h"
#include "schnorr_proof.h"
#include "range_proof.h"
#include "params.h"

using namespace secp_primitives;

namespace lelantus {

class LelantusProof {
public:
    //n is the number of input coins, bulletproof_n is number of output coins,
    inline std::size_t memoryRequired(int n, int bulletproof_n, int bulletproof_m) const {
        return  sigma_proofs[0].memoryRequired() * n
                + bulletproofs.memoryRequired(bulletproof_n, bulletproof_m)
                + schnorrProof.memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sigma_proofs);
        READWRITE(bulletproofs);
        READWRITE(schnorrProof);
    }

public:
    std::vector<SigmaExtendedProof> sigma_proofs;
    RangeProof bulletproofs;
    SchnorrProof schnorrProof;
};
}//namespace lelantus

#endif //FIRO_LIBLELANTUS_LELANTUSPROOF_H
