#ifndef ZCOIN_LIBLELANTUS_SIGMAEXTENDED_PROVER_H
#define ZCOIN_LIBLELANTUS_SIGMAEXTENDED_PROVER_H

#include "lelantus_primitives.h"

namespace lelantus {

class SigmaExtendedProver{

public:
    SigmaExtendedProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens, uint64_t n, uint64_t m);
    void proof(const std::vector<GroupElement>& commits,
               int l,
               const Scalar& v,
               const Scalar& r,
               SigmaExtendedProof& proof_out);
    void sigma_commit(
            const std::vector<GroupElement>& commits,
            int l,
            const Scalar& rA,
            const Scalar& rB,
            const Scalar& rC,
            const Scalar& rD,
            std::vector<Scalar>& a,
            std::vector<Scalar>& Tk,
            std::vector<Scalar>& Pk,
            std::vector<Scalar>& Yk,
            std::vector<Scalar>& sigma,
            SigmaExtendedProof& proof_out);

    void sigma_response(
            const std::vector<Scalar>& sigma,
            const std::vector<Scalar>& a,
            const Scalar& rA,
            const Scalar& rB,
            const Scalar& rC,
            const Scalar& rD,
            const Scalar& v,
            const Scalar& r,
            const std::vector<Scalar>& Tk,
            const std::vector<Scalar>& Pk,
            const Scalar& x,
            SigmaExtendedProof& proof_out);


private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    uint64_t n_;
    uint64_t m_;
};

}//namespace lelantus

#endif //ZCOIN_LIBLELANTUS_SIGMAEXTENDED_PROVER_H
