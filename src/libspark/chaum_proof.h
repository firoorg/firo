#ifndef FIRO_LIBSPARK_CHAUM_PROOF_H
#define FIRO_LIBSPARK_CHAUM_PROOF_H

#include "params.h"

namespace spark {

class ChaumProof{
public:
    inline std::size_t memoryRequired() const {
        return GroupElement::memoryRequired() + A2.size()*GroupElement::memoryRequired() + t1.size()*Scalar::memoryRequired() + 2*Scalar::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A1);
        READWRITE(A2);
        READWRITE(t1);
        READWRITE(t2);
        READWRITE(t3);
    }

public:
    GroupElement A1;
    std::vector<GroupElement> A2;
    std::vector<Scalar> t1;
    Scalar t2, t3;
};
}

#endif
