#ifndef FIRO_LIBSPARK_OWNERSHIP_PROOF_H
#define FIRO_LIBSPARK_OWNERSHIP_PROOF_H

#include "params.h"

namespace spark {

class OwnershipProof{
public:
    static constexpr std::size_t memoryRequired() {
        return Scalar::memoryRequired() * 3 + GroupElement::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(t1);
        READWRITE(t2);
        READWRITE(t3);
    }

public:
    GroupElement A;
    Scalar t1;
    Scalar t2;
    Scalar t3;
};
}

#endif
