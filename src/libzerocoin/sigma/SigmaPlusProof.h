#ifndef ZCOIN_SIGMAPLUSPROOF_H
#define ZCOIN_SIGMAPLUSPROOF_H

#include "R1Proof.h"

namespace sigma {

template<class Exponent, class GroupElement>
class SigmaPlusProof{
public:
    SigmaPlusProof() = default;

    inline int memoryRequired() const {
        return B_.memoryRequired()
               + r1Proof_.memoryRequired()
               + B_.memoryRequired() * Gk_.size()
               + z_.memoryRequired();
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = B_.serialize(buffer);
        current = r1Proof_.serialize(current);
        for(int i = 0; i < Gk_.size(); ++i)
            current = Gk_[i].serialize(current);
        return z_.serialize(current);
    }

    inline unsigned char* deserialize(unsigned char* buffer, int n, int m) {
        unsigned char* current = B_.deserialize(buffer);
        current = r1Proof_.deserialize(current, m * (n - 1));
        Gk_.resize(m);
        for(int i = 0; i < m; ++i)
            current = Gk_[i].deserialize(current);
        return z_.deserialize(current);
    }

public:
    GroupElement B_;
    R1Proof<Exponent, GroupElement> r1Proof_;
    std::vector<GroupElement> Gk_;
    Exponent z_;
};

} //namespace sigma

#endif //ZCOIN_SIGMAPLUSPROOF_H
