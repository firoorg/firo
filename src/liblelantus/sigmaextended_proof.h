#ifndef FIRO_LIBLELANTUS_SIGMAEXTENDED_PROOF_H
#define FIRO_LIBLELANTUS_SIGMAEXTENDED_PROOF_H

#include <vector>
#include "params.h"

namespace lelantus {

class SigmaExtendedProof{
public:
    SigmaExtendedProof() = default;

    inline std::size_t memoryRequired() const {
        return B_.memoryRequired() * 4
               + ZA_.memoryRequired() * (f_.size() + 2)
               + B_.memoryRequired() * Gk_.size() * 2
               + zR_.memoryRequired() * 2;
    }

    inline std::size_t memoryRequired(int n, int m) const {
        return B_.memoryRequired() * 4
               + ZA_.memoryRequired() * (m*(n - 1) + 2)
               + B_.memoryRequired() * m * 2
               + zR_.memoryRequired() * 2;
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A_);
        READWRITE(B_);
        READWRITE(C_);
        READWRITE(D_);
        READWRITE(f_);
        READWRITE(ZA_);
        READWRITE(ZC_);
        READWRITE(Gk_);
        READWRITE(Qk);
        READWRITE(zV_);
        READWRITE(zR_);
    }

public:
    GroupElement A_;
    GroupElement B_;
    GroupElement C_;
    GroupElement D_;
    std::vector<Scalar> f_;
    Scalar ZA_;
    Scalar ZC_;
    std::vector<GroupElement> Gk_;
    std::vector<GroupElement> Qk;
    Scalar zV_;
    Scalar zR_;
};

} //namespace lelantus

#endif //FIRO_LIBLELANTUS_SIGMAEXTENDED_PROOF_H
