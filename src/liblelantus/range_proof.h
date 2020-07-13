#ifndef ZCOIN_LIBLELANTUS_RANGEPROOF_H
#define ZCOIN_LIBLELANTUS_RANGEPROOF_H

#include "innerproduct_proof.h"
#include <cmath>

namespace lelantus {
    
class RangeProof{
public:

    inline std::size_t memoryRequired(int n, int m) const {
        int size = (int)std::log2(n * m);
        return A.memoryRequired() * 4
               + T_x1.memoryRequired() * 3
               + innerProductProof.memoryRequired(size);
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        buffer = A.serialize(buffer);
        buffer = S.serialize(buffer);
        buffer = T1.serialize(buffer);
        buffer = T2.serialize(buffer);
        buffer = T_x1.serialize(buffer);
        buffer = T_x2.serialize(buffer);
        buffer = u.serialize(buffer);
        return innerProductProof.serialize(buffer);
    }

    inline const unsigned char* deserialize(const unsigned char* buffer, int n) {
        int size = (int)std::log2(n);
        buffer = A.deserialize(buffer);
        buffer = S.deserialize(buffer);
        buffer = T1.deserialize(buffer);
        buffer = T2.deserialize(buffer);
        buffer = T_x1.deserialize(buffer);
        buffer = T_x2.deserialize(buffer);
        buffer = u.deserialize(buffer);
        return innerProductProof.deserialize(buffer, size);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(S);
        READWRITE(T1);
        READWRITE(T2);
        READWRITE(T_x1);
        READWRITE(T_x2);
        READWRITE(u);
        READWRITE(innerProductProof);
    }

    GroupElement A;
    GroupElement S;
    GroupElement T1;
    GroupElement T2;
    Scalar T_x1;
    Scalar T_x2;
    Scalar u;
    InnerProductProof innerProductProof;

};
}//namespace lelantus

#endif //ZCOIN_LIBLELANTUS_RANGE_PROOF_H
