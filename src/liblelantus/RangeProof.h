#ifndef ZCOIN_RANGEPROOF_H
#define ZCOIN_RANGEPROOF_H

#include "InnerProductProof.h"
#include <math.h>

namespace lelantus {

template<class Exponent, class GroupElement>
class RangeProof{
public:

    inline int memoryRequired(int n, int m) {
        int size = (int)(log(n * m) / log(2));
        return A.memoryRequired() * 4
               + T_x1.memoryRequired() * 3
               + innerProductProof.memoryRequired(size);
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = A.serialize(buffer);
        current = S.serialize(current);
        current = T1.serialize(current);
        current = T2.serialize(current);
        current = T_x1.serialize(current);
        current = T_x2.serialize(current);
        current = u.serialize(current);
        current = innerProductProof.serialize(current);
        return current;
    }

    inline unsigned char* deserialize(unsigned char* buffer, int n) {
        int size = (int)(log(n) / log(2));
        unsigned char* current = A.deserialize(buffer);
        current = S.deserialize(current);
        current = T1.deserialize(current);
        current = T2.deserialize(current);
        current = T_x1.deserialize(current);
        current = T_x2.deserialize(current);
        current = u.deserialize(current);
        current = innerProductProof.deserialize(current, n);
        return current;
    }

    GroupElement A;
    GroupElement S;
    GroupElement T1;
    GroupElement T2;
    Exponent T_x1;
    Exponent T_x2;
    Exponent u;
    InnerProductProof<Exponent, GroupElement> innerProductProof;

};
}//namespace lelantus

#endif //ZCOIN_RANGEPROOF_H
