#ifndef FIRO_LIBSPARK_CHAUM_PROOF_H
#define FIRO_LIBSPARK_CHAUM_PROOF_H

#include "params.h"

namespace spark {

static constexpr std::size_t MAX_CHAUM_V2_INPUTS = 100;

// Historical, deployed proof layout. Its serialization is consensus data and
// must remain byte-for-byte stable for old blocks.
class ChaumProofV1 {
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

// Version 2 preserves independent commitments and responses for each
// statement.
class ChaumProofV2 {
public:
    inline std::size_t memoryRequired() const {
        return (A1.size() + A2.size())*GroupElement::memoryRequired()
            + (t1.size() + t2.size() + t3.size())*Scalar::memoryRequired();
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
    std::vector<GroupElement> A1, A2;
    std::vector<Scalar> t1, t2, t3;
};
}

#endif
