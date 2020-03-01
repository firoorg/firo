#ifndef ZCOIN_SIGMAPLUSPROOF_H
#define ZCOIN_SIGMAPLUSPROOF_H

#include <vector>
#include "params.h"

namespace lelantus {

template<class Exponent, class GroupElement>
class SigmaPlusProof{
public:
    SigmaPlusProof() = default;

    inline int memoryRequired() const {
        return B_.memoryRequired() * 4
               + ZA_.memoryRequired() * (f_.size() + 2)
               + B_.memoryRequired() * Gk_.size() * 2
               + zR_.memoryRequired() * 2;
    }

    inline int memoryRequired(int n, int m) const {
        return B_.memoryRequired() * 4
               + ZA_.memoryRequired() * (m*(n - 1) + 2)
               + B_.memoryRequired() * m * 2
               + zR_.memoryRequired() * 2;
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = buffer;
        current = A_.serialize(current);
        current = B_.serialize(current);
        current = C_.serialize(current);
        current = D_.serialize(current);
        for(std::size_t i = 0; i < f_.size(); ++i)
            current = f_[i].serialize(current);
        current = ZA_.serialize(current);
        current = ZC_.serialize(current);
        for(std::size_t i = 0; i < Gk_.size(); ++i)
            current = Gk_[i].serialize(current);
        for(std::size_t i = 0; i < Qk.size(); ++i)
            current = Qk[i].serialize(current);
        current = zV_.serialize(current);
        return zR_.serialize(current);
    }

    inline const unsigned char* deserialize(const unsigned char* buffer, int n, int m) {
        const unsigned char* current = buffer;
        current = A_.deserialize(current);
        current = B_.deserialize(current);
        current = C_.deserialize(current);
        current = D_.deserialize(current);
        f_.resize(m * (n - 1));
        for(int i = 0; i < m * (n - 1); ++i)
            current = f_[i].deserialize(current);
        current = ZA_.deserialize(current);
        current = ZC_.deserialize(current);
        Gk_.resize(m);
        Qk.resize(m);
        for(int i = 0; i < m; ++i)
            current = Gk_[i].deserialize(current);
        for(int i = 0; i < m; ++i)
            current = Qk[i].deserialize(current);
        current = zV_.deserialize(current);
        return zR_.deserialize(current);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
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

#endif //ZCOIN_SIGMAPLUSPROOF_H
