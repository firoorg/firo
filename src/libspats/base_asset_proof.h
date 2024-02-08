#ifndef FIRO_LIBSPATS_BASE_PROOF_H
#define FIRO_LIBSPATS_BASE_PROOF_H

#include "params.h"

namespace spats {

class BaseAssetProof{
public:
    inline std::size_t memoryRequired() const {
        return Scalar::memoryRequired() + GroupElement::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(ty);
        READWRITE(tz);
    }

public:
    GroupElement A;
    Scalar ty;
    Scalar tz;
};
}

#endif
