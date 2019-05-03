#ifndef ZCOIN_SIGMA_SIGMAPLUS_PROOF_H
#define ZCOIN_SIGMA_SIGMAPLUS_PROOF_H

#include "params.h"
#include "r1_proof.h"

namespace sigma {

template<class Exponent, class GroupElement>
class SigmaPlusProof{
public:
    SigmaPlusProof(const Params* p): params(p) {};

    inline int memoryRequired() const {
        return B_.memoryRequired()
               + r1Proof_.memoryRequired(params->get_n(), params->get_m())
               + B_.memoryRequired() * params->get_m()
               + z_.memoryRequired();
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = B_.serialize(buffer);
        current = r1Proof_.serialize(current);
        for (std::size_t i = 0; i < Gk_.size(); ++i)
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

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(B_);
        READWRITE(r1Proof_);
        READWRITE(Gk_);
        READWRITE(z_);
    }

public:
    const Params* params;
    GroupElement B_;
    R1Proof<Exponent, GroupElement> r1Proof_;
    std::vector<GroupElement> Gk_;
    Exponent z_;
};

} //namespace sigma

#endif // ZCOIN_SIGMA_SIGMAPLUS_PROOF_H
