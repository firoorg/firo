#ifndef ZCOIN_SIGMAPLUSPROOF_H
#define ZCOIN_SIGMAPLUSPROOF_H

#include "R1Proof.h"
#include "Params.h"
namespace sigma {

template<class Exponent, class GroupElement>
class SigmaPlusProof{
public:
    SigmaPlusProof(const ParamsV3* p): params(p) {};

    inline int memoryRequired() const {
        return B_.memoryRequired()
               + r1Proof_.memoryRequired(params->get_n(), params->get_m())
               + B_.memoryRequired() * params->get_m()
               + z_.memoryRequired();
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = B_.serialize(buffer);
        current = r1Proof_.serialize(current);
        for(int i = 0; i < Gk_.size(); ++i)
            current = Gk_[i].serialize(current);
        return z_.serialize(current);
    }

    inline unsigned char* deserialize(unsigned char* buffer) {
        unsigned char* current = B_.deserialize(buffer);
        current = r1Proof_.deserialize(current, params->get_n(), params->get_m());
        Gk_.resize(params->get_m());
        for(int i = 0; i < params->get_m(); ++i)
            current = Gk_[i].deserialize(current);
        return z_.deserialize(current);
    }

public:
    const ParamsV3* params;
    GroupElement B_;
    R1Proof<Exponent, GroupElement> r1Proof_;
    std::vector<GroupElement> Gk_;
    Exponent z_;
};

} //namespace sigma

#endif //ZCOIN_SIGMAPLUSPROOF_H
