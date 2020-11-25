#ifndef ZCOIN_LIBLELANTUS_SIGMAEXTENDED_VERIFIER_H
#define ZCOIN_LIBLELANTUS_SIGMAEXTENDED_VERIFIER_H

#include "lelantus_primitives.h"

namespace lelantus {

class SigmaExtendedVerifier{

public:
    SigmaExtendedVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      uint64_t n, uint64_t m_);
    //gets commitments divided into g^s
    bool verify(const std::vector<GroupElement>& commits,
                const Scalar& x,
                const SigmaExtendedProof& proof) const;
    //gets commitments divided into g^s
    bool verify(const std::vector<GroupElement>& commits,
                const SigmaExtendedProof& proof) const;
    //gets initial double-blinded Pedersen commitments,
    //verifies proofs from single transaction, where set size and challenge are the same
    bool batchverify(const std::vector<GroupElement>& commits,
                     const Scalar& x,
                     const std::vector<Scalar>& serials,
                     const vector<SigmaExtendedProof>& proofs) const;
    //gets initial double-blinded Pedersen commitments
    //verifies proofs from different transactions, where set sizes and challenges are different
    bool batchverify(const std::vector<GroupElement>& commits,
                     const std::vector<Scalar>& challenges,
                     const std::vector<Scalar>& serials,
                     const std::vector<size_t>& setSizes,
                     const vector<SigmaExtendedProof>& proofs) const;

private:
    //auxiliary functions
    bool membership_checks(const SigmaExtendedProof& proof) const;
    bool compute_fs(
            const SigmaExtendedProof& proof,
            const Scalar& x,
            std::vector<Scalar>& f_) const;
    bool abcd_checks(
            const SigmaExtendedProof& proof,
            const Scalar& x,
            const std::vector<Scalar>& f_) const;

    void compute_fis(int j, const std::vector<Scalar>& f, std::vector<Scalar>& f_i_) const;
    void compute_fis(
            const Scalar& f_i,
            int j,
            const std::vector<Scalar>& f,
            vector<Scalar>::iterator& ptr,
            vector<Scalar>::iterator end_ptr) const;
    void compute_batch_fis(
            const Scalar& f_i,
            int j,
            const std::vector<Scalar>& f,
            const Scalar& y,
            Scalar& e,
            vector<Scalar>::iterator& ptr,
            vector<Scalar>::iterator start_ptr,
            vector<Scalar>::iterator end_ptr) const;

private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    uint64_t n;
    uint64_t m;
};

} // namespace lelantus

#endif //ZCOIN_LIBLELANTUS_SIGMAEXTENDED_VERIFIER_H
