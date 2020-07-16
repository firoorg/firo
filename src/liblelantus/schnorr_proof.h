#ifndef ZCOIN_LIBLELANTUS_SCHNORR_PROOF_H
#define ZCOIN_LIBLELANTUS_SCHNORR_PROOF_H

#include "params.h"

namespace lelantus {

class SchnorrProof{
public:
    inline std::size_t memoryRequired() const {
        return u.memoryRequired()  + P1.memoryRequired() * 2;
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(u);
        READWRITE(P1);
        READWRITE(T1);
    }

public:
    GroupElement u;
    Scalar P1;
    Scalar T1;
};
}//namespace lelantus

#endif //ZCOIN_LIBLELANTUS_SCHNORR_PROOF_H
