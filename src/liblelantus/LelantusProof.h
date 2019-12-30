#ifndef ZCOIN_LELANTUSPROOF_H
#define ZCOIN_LELANTUSPROOF_H

#include "SchnorrProof.h"
#include "RangeProof.h"
#include "Params.h"

using namespace secp_primitives;

namespace lelantus {

class LelantusProof {
public:
    //n is the number of input coins, bulletproof_n is number of output coins,
    inline int memoryRequired(int n, int bulletproof_n, int bulletproof_m) {
        return  sigma_proofs[0].memoryRequired() * n
                + bulletproofs.memoryRequired(bulletproof_n, bulletproof_m)
                + schnorrProof.memoryRequired();
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = buffer;
        for(int i = 0; i < sigma_proofs.size(); ++i)
            current = sigma_proofs[i].serialize(current);
        current = bulletproofs.serialize(current);
        return schnorrProof.serialize(current);
    }

    inline const unsigned char* deserialize(const Params* params, const unsigned char* buffer, int size, int b_m) {
        const unsigned char* current = buffer;
        sigma_proofs.resize(size);
        for(int i = 0; i < size; ++i)
            current = sigma_proofs[i].deserialize(current, params->get_n(), params->get_m());
        current = bulletproofs.deserialize(current, params->get_bulletproofs_n() * b_m);
        return schnorrProof.deserialize(current);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
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

#endif //ZCOIN_LELANTUSPROOF_H
