#ifndef ZCOIN_LIBLELANTUS_SIGMAPLUS_PROOF_H
#define ZCOIN_LIBLELANTUS_SIGMAPLUS_PROOF_H

#include <vector>
#include "params.h"

namespace lelantus {

template<class Exponent, class GroupElement>
class SigmaPlusProof{
public:
    SigmaPlusProof() = default;

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

    inline unsigned char* serialize(unsigned char* buffer) const {
        buffer = A_.serialize(buffer);
        buffer = B_.serialize(buffer);
        buffer = C_.serialize(buffer);
        buffer = D_.serialize(buffer);
        for(std::size_t i = 0; i < f_.size(); ++i)
            buffer = f_[i].serialize(buffer);
        buffer = ZA_.serialize(buffer);
        buffer = ZC_.serialize(buffer);
        for(std::size_t i = 0; i < Gk_.size(); ++i)
            buffer = Gk_[i].serialize(buffer);
        for(std::size_t i = 0; i < Qk.size(); ++i)
            buffer = Qk[i].serialize(buffer);
        buffer = zV_.serialize(buffer);
        return zR_.serialize(buffer);
    }

    inline const unsigned char* deserialize(const unsigned char* buffer, int n, int m) {
        buffer = A_.deserialize(buffer);
        buffer = B_.deserialize(buffer);
        buffer = C_.deserialize(buffer);
        buffer = D_.deserialize(buffer);
        f_.resize(m * (n - 1));
        for(int i = 0; i < m * (n - 1); ++i)
            buffer = f_[i].deserialize(buffer);
        buffer = ZA_.deserialize(buffer);
        buffer = ZC_.deserialize(buffer);
        Gk_.resize(m);
        Qk.resize(m);
        for(int i = 0; i < m; ++i)
            buffer = Gk_[i].deserialize(buffer);
        for(int i = 0; i < m; ++i)
            buffer = Qk[i].deserialize(buffer);
        buffer = zV_.deserialize(buffer);
        return zR_.deserialize(buffer);
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
    std::vector<Exponent> f_;
    Exponent ZA_;
    Exponent ZC_;
    std::vector<GroupElement> Gk_;
    std::vector<GroupElement> Qk;
    Exponent zV_;
    Exponent zR_;
};

} //namespace lelantus

#endif //ZCOIN_LIBLELANTUS_SIGMAPLUS_PROOF_H
