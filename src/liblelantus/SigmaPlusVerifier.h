#ifndef ZCOIN_SIGMAPLUSVERIFIER_H
#define ZCOIN_SIGMAPLUSVERIFIER_H

#include "LelantusPrimitives.h"

namespace lelantus {

template<class Exponent, class GroupElement>
class SigmaPlusVerifier{

public:
    SigmaPlusVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      uint64_t n, uint64_t m_);
    //gets commitments divided into g^s
    bool verify(const std::vector<GroupElement>& commits,
                const Exponent& x,
                const SigmaPlusProof<Exponent, GroupElement>& proof) const;
    //gets commitments divided into g^s
    bool verify(const std::vector<GroupElement>& commits,
                const SigmaPlusProof<Exponent, GroupElement>& proof) const;
    //gets initial double-blinded Pedersen commitments
    bool batchverify(const std::vector<GroupElement>& commits,
                     const Exponent& x,
                     const std::vector<Exponent>& serials,
                     const vector<SigmaPlusProof<Exponent, GroupElement>>& proofs) const;
    //auxiliary functions
    bool membership_checks(const SigmaPlusProof<Exponent, GroupElement>& proof) const;
    void compute_fs(const SigmaPlusProof<Exponent, GroupElement>& proof, const Exponent& x, std::vector<Exponent>& f_) const;
    bool abcd_checks(const SigmaPlusProof<Exponent, GroupElement>& proof, const Exponent& x, const std::vector<Exponent>& f_) const;
private:
    GroupElement g_;
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_;
    uint64_t n;
    uint64_t m;
};

} // namespace lelantus

#include "SigmaPlusVerifier.hpp"

#endif //ZCOIN_SIGMAPLUSVERIFIER_H
