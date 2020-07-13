#ifndef ZCOIN_LIBLELANTUS_SIGMAPLUS_VERIFIER_H
#define ZCOIN_LIBLELANTUS_SIGMAPLUS_VERIFIER_H

#include "lelantus_primitives.h"

namespace lelantus {

class SigmaPlusVerifier{

public:
    SigmaPlusVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      uint64_t n, uint64_t m_);
    //gets commitments divided into g^s
    bool verify(const std::vector<GroupElement>& commits,
                const Scalar& x,
                const SigmaPlusProof& proof) const;
    //gets commitments divided into g^s
    bool verify(const std::vector<GroupElement>& commits,
                const SigmaPlusProof& proof) const;
    //gets initial double-blinded Pedersen commitments
    bool batchverify(const std::vector<GroupElement>& commits,
                     const Scalar& x,
                     const std::vector<Scalar>& serials,
                     const vector<SigmaPlusProof>& proofs) const;

private:
    //auxiliary functions
    bool membership_checks(const SigmaPlusProof& proof) const;
    bool compute_fs(
            const SigmaPlusProof& proof,
            const Scalar& x,
            std::vector<Scalar>& f_) const;
    bool abcd_checks(
            const SigmaPlusProof& proof,
            const Scalar& x,
            const std::vector<Scalar>& f_) const;
private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    uint64_t n;
    uint64_t m;
};

} // namespace lelantus

#endif //ZCOIN_LIBLELANTUS_SIGMAPLUS_VERIFIER_H
