#ifndef ZCOIN_LIBLELANTUS_SIGMAPLUS_PROVER_H
#define ZCOIN_LIBLELANTUS_SIGMAPLUS_PROVER_H

#include "lelantus_primitives.h"


namespace lelantus {

template <class Exponent, class GroupElement>
class SigmaPlusProver{

public:
    SigmaPlusProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens, uint64_t n, uint64_t m);
    void proof(const std::vector<GroupElement>& commits,
               int l,
               const Exponent& v,
               const Exponent& r,
               SigmaPlusProof<Exponent, GroupElement>& proof_out);
    void sigma_commit(
            const std::vector<GroupElement>& commits,
            int l,
            const Exponent& rA,
            const Exponent& rB,
            const Exponent& rC,
            const Exponent& rD,
            std::vector <Exponent>& a,
            std::vector <Exponent>& Tk,
            std::vector <Exponent>& Pk,
            std::vector <Exponent>& Yk,
            std::vector <Exponent>& sigma,
            SigmaPlusProof<Exponent, GroupElement>& proof_out);

    void sigma_response(
            const std::vector <Exponent>& sigma,
            const std::vector<Exponent>& a,
            const Exponent& rA,
            const Exponent& rB,
            const Exponent& rC,
            const Exponent& rD,
            const Exponent& v,
            const Exponent& r,
            const std::vector <Exponent>& Tk,
            const std::vector <Exponent>& Pk,
            const Exponent& x,
            SigmaPlusProof<Exponent, GroupElement>& proof_out);


private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    uint64_t n_;
    uint64_t m_;
};

}//namespace lelantus

#include "sigmaplus_prover.hpp"

#endif //ZCOIN_LIBLELANTUS_SIGMAPLUS_PROVER_H
