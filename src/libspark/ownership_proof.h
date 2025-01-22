#ifndef FIRO_LIBSPARK_OWNERSHIP_PROOF_H
#define FIRO_LIBSPARK_OWNERSHIP_PROOF_H

#include <ostream>

#include "params.h"

namespace spark {

class OwnershipProof{
public:
    inline std::size_t memoryRequired() const {
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

inline std::ostream& operator<<(std::ostream& os, const OwnershipProof& proof)
{
    return os << "ownership proof: " << proof.A << " " << proof.t1 << " " << proof.t2 << " " << proof.t3;
}

}

#endif
