#ifndef ZCOIN_SCHNORRPROOF_H
#define ZCOIN_SCHNORRPROOF_H

#include "Params.h"

namespace lelantus {

template <class Exponent, class GroupElement>
class SchnorrProof{
public:
    inline int memoryRequired() {
        return u.memoryRequired()  + P1.memoryRequired() * 2;
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = u.serialize(buffer);
        current = P1.serialize(current);
        return T1.serialize(current);
    }

    inline const unsigned char* deserialize(const unsigned char* buffer) {
        const unsigned char* current = u.deserialize(buffer);
        current = P1.deserialize(current);
        return T1.deserialize(current);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
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

#endif //ZCOIN_SCHNORRPROOF_H
