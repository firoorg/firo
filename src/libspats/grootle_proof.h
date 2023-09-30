#ifndef FIRO_LIBSPARK_GROOTLE_PROOF_H
#define FIRO_LIBSPARK_GROOTLE_PROOF_H

#include "params.h"

namespace spark {

class GrootleProof {
public:

    inline std::size_t memoryRequired() const {
        return 2*GroupElement::memoryRequired() + X.size()*GroupElement::memoryRequired() + X1.size()*GroupElement::memoryRequired() + f.size()*Scalar::memoryRequired() + 3*Scalar::memoryRequired();
    }

    inline std::size_t memoryRequired(int n, int m) const {
        return 2*GroupElement::memoryRequired() + 2*m*GroupElement::memoryRequired() + m*(n-1)*Scalar::memoryRequired() + 3*Scalar::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(B);
        READWRITE(X);
        READWRITE(X1);
        READWRITE(f);
        READWRITE(z);
        READWRITE(zS);
        READWRITE(zV);
    }

public:
    GroupElement A;
    GroupElement B;
    std::vector<GroupElement> X;
    std::vector<GroupElement> X1;
    std::vector<Scalar> f;
    Scalar z;
    Scalar zS;
    Scalar zV;
};

}

#endif
