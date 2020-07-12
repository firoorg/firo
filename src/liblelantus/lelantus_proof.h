#ifndef ZCOIN_LIBLELANTUS_LELANTUSPROOF_H
#define ZCOIN_LIBLELANTUS_LELANTUSPROOF_H

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

    inline unsigned char* serialize(unsigned char* buffer) const {
        for(std::size_t i = 0; i < sigma_proofs.size(); ++i)
            buffer = sigma_proofs[i].serialize(buffer);
        buffer = bulletproofs.serialize(buffer);
        return schnorrProof.serialize(buffer);
    }

    inline const unsigned char* deserialize(const Params* params, const unsigned char* buffer, int size, int b_m) {
        sigma_proofs.resize(size);
        for(int i = 0; i < size; ++i)
            buffer = sigma_proofs[i].deserialize(buffer, params->get_sigma_n(), params->get_sigma_m());
        buffer = bulletproofs.deserialize(buffer, params->get_bulletproofs_n() * b_m);
        return schnorrProof.deserialize(buffer);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sigma_proofs);
        READWRITE(bulletproofs);
        READWRITE(schnorrProof);
    }

public:
    std::vector<SigmaPlusProof<Scalar, GroupElement>> sigma_proofs;
    RangeProof<Scalar, GroupElement> bulletproofs;
    SchnorrProof<Scalar, GroupElement> schnorrProof;
};
}//namespace lelantus

#endif //ZCOIN_LIBLELANTUS_LELANTUSPROOF_H
