#ifndef ZCOIN_LIBLELANTUS_RANGEPROOF_H
#define ZCOIN_LIBLELANTUS_RANGEPROOF_H

#include "innerproduct_proof.h"
#include <cmath>

namespace lelantus {
    
class RangeProof{
public:

    static inline int int_log2(uint64_t number) {
        assert(number != 0);

        int l2 = 0;
        while ((number >>= 1) != 0)
            l2++;

        return l2;
    }

    inline std::size_t memoryRequired(int n, int m) const {
        int size = int_log2(n * m);
        return A.memoryRequired() * 4
               + T_x1.memoryRequired() * 3
               + innerProductProof.memoryRequired(size);
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
