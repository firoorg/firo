#ifndef ZCOIN_SCHNORRPROOF_H
#define ZCOIN_SCHNORRPROOF_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>

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

    inline unsigned char* deserialize(unsigned char* buffer) {
        unsigned char* current = u.deserialize(buffer);
        current = P1.deserialize(current);
        return T1.deserialize(current);
    }

    GroupElement u;
    Exponent P1;
    Exponent T1;
};
}//namespace lelantus

#endif //ZCOIN_SCHNORRPROOF_H
