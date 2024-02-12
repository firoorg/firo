#ifndef FIRO_LIBSPATS_TYPE_PROOF_H
#define FIRO_LIBSPATS_TYPE_PROOF_H

#include "params.h"
#include <cstddef>

namespace spats
{

class TypeProof
{
public:
    inline std::size_t memoryRequired() const
    {
        return 6*Scalar::memoryRequired() + 2*GroupElement::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(A);
        READWRITE(B);
        READWRITE(tw);
        READWRITE(tx);
        READWRITE(ty);
        READWRITE(tz);
        READWRITE(uy);
        READWRITE(uz);
    }

public:
    GroupElement A;
    GroupElement B;
    Scalar tw;
    Scalar tx;
    Scalar ty;
    Scalar tz;
    Scalar uy;
    Scalar uz;
};
} // namespace spats

#endif