#ifndef ZCOIN_SIGMAPLUSPROOF_H
#define ZCOIN_SIGMAPLUSPROOF_H

#include "R1Proof.h"

namespace sigma {

template<class Exponent, class GroupElement>
class SigmaPlusProof{
public:
    SigmaPlusProof() = default;

    inline int debug_size() {
        return B_.writeMemoryRequired() * 4 + z_.writeMemoryRequired() * r1Proof_.get_f().size() + z_.writeMemoryRequired() * 3
               + B_.writeMemoryRequired() * Gk_.size();
    }

public:
    GroupElement B_;
    R1Proof<Exponent, GroupElement> r1Proof_;
    std::vector<GroupElement> Gk_;
    Exponent z_;
    int n_;
    int m_;
};

} //namespace sigma

#endif //ZCOIN_SIGMAPLUSPROOF_H
