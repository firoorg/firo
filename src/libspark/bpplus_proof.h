#ifndef FIRO_LIBSPARK_BPPLUS_PROOF_H
#define FIRO_LIBSPARK_BPPLUS_PROOF_H

#include "params.h"

namespace spark {
    
class BPPlusProof{
public:

    static inline int int_log2(std::size_t number) {
        assert(number != 0);

        int l2 = 0;
        while ((number >>= 1) != 0)
            l2++;

        return l2;
    }

    inline std::size_t memoryRequired() const {
        return 3*GroupElement::memoryRequired() + 3*Scalar::memoryRequired() + L.size()*GroupElement::memoryRequired() + R.size()*GroupElement::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(A1);
        READWRITE(B);
        READWRITE(r1);
        READWRITE(s1);
        READWRITE(d1);
        READWRITE(L);
        READWRITE(R);
    }

    GroupElement A, A1, B;
    Scalar r1, s1, d1;
    std::vector<GroupElement> L, R;
};
}

#endif
