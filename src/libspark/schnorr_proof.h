#ifndef FIRO_LIBSPARK_SCHNORR_PROOF_H
#define FIRO_LIBSPARK_SCHNORR_PROOF_H

#include "params.h"

namespace spark {

class SchnorrProof{
public:
    inline std::size_t memoryRequired() const {
        return Scalar::memoryRequired() + GroupElement::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(t);
    }

public:
    GroupElement A;
    Scalar t;
};
}

#endif
