#ifndef FIRO_LIBSPARK_SCHNORR_PROOF_H
#define FIRO_LIBSPARK_SCHNORR_PROOF_H

#include "params.h"

namespace spark {

class SchnorrProof{
public:
    inline std::size_t memoryRequired() const {
        return 2*Scalar::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(c);
        READWRITE(t);
    }

public:
    Scalar c;
    Scalar t;
};
}

#endif
