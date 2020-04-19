#ifndef ZCOIN_LIBLELANTUS_SCHNORR_PROOF_H
#define ZCOIN_LIBLELANTUS_SCHNORR_PROOF_H

#include "params.h"

namespace lelantus {

template <class Exponent, class GroupElement>
class SchnorrProof{
public:
    inline int memoryRequired() const {
        return u.memoryRequired()  + P1.memoryRequired() * 2;
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        buffer = u.serialize(buffer);
        buffer = P1.serialize(buffer);
        return T1.serialize(buffer);
    }

    inline const unsigned char* deserialize(const unsigned char* buffer) {
        buffer = u.deserialize(buffer);
        buffer = P1.deserialize(buffer);
        return T1.deserialize(buffer);
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
    Exponent P1;
    Exponent T1;
};
}//namespace lelantus

#endif //ZCOIN_LIBLELANTUS_SCHNORR_PROOF_H
