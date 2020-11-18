#ifndef FIRO_SIGMA_SIGMAPLUS_PROOF_H
#define FIRO_SIGMA_SIGMAPLUS_PROOF_H

#include "params.h"
#include "r1_proof.h"

namespace sigma {

template<class Exponent, class GroupElement>
class SigmaPlusProof {
public:
    int n;
    int m;
    GroupElement B_;
    R1Proof<Exponent, GroupElement> r1Proof_;
    std::vector<GroupElement> Gk_;
    Exponent z_;

public:
    SigmaPlusProof(int n, int m): n(n), m(m) {};

public:
    bool operator==(const SigmaPlusProof& other) const {
        return n == other.n &&
            m == other.m &&
            B_ == other.B_ &&
            r1Proof_ == other.r1Proof_ &&
            Gk_ == other.Gk_ &&
            z_ == other.z_;
    }

    bool operator!=(const SigmaPlusProof& other) const {
        return !(*this == other);
    }

public:
    inline int memoryRequired() const {
        return B_.memoryRequired()
               + r1Proof_.memoryRequired(n, m)
               + B_.memoryRequired() * m
               + z_.memoryRequired();
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = B_.serialize(buffer);
        current = r1Proof_.serialize(current);
        for (std::size_t i = 0; i < Gk_.size(); ++i)
            current = Gk_[i].serialize(current);
        return z_.serialize(current);
    }

    inline unsigned const char* deserialize(unsigned const char* buffer) {
        unsigned const char* current = B_.deserialize(buffer);
        current = r1Proof_.deserialize(current, n, m);
        Gk_.resize(m);
        for(int i = 0; i < m; ++i)
            current = Gk_[i].deserialize(current);
        return z_.deserialize(current);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(B_);
        READWRITE(r1Proof_);
        READWRITE(Gk_);
        READWRITE(z_);
    }
};

} //namespace sigma

#endif // FIRO_SIGMA_SIGMAPLUS_PROOF_H
