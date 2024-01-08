#ifndef FIRO_LIBSPATS_BALANCE_PROOF_H
#define FIRO_LIBSPATS_BALANCE_PROOF_H

#include "params.h"

namespace spats{

class BalanceProof{
public:
    inline std::size_t memoryRequired() const {
        return 3*Scalar::memoryRequired() + GroupElement::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(tw);
        READWRITE(tx);
        READWRITE(tz);
    }

public:
    GroupElement A;
    Scalar tw;
    Scalar tx;
    Scalar tz;
};
}

#endif
