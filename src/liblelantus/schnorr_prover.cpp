#include "schnorr_prover.h"

namespace lelantus {

SchnorrProver::SchnorrProver(const GroupElement& g, const GroupElement& h):
    g_(g), h_(h) {
}

void SchnorrProver::proof(
        const Scalar& P,
        const Scalar& T,
        SchnorrProof& proof_out){
    Scalar P0;
    Scalar T0;
    P0.randomize();
    T0.randomize();
    GroupElement u = LelantusPrimitives::commit(g_,P0, h_, T0);
    proof_out.u = u;
    Scalar c;
    std::vector<GroupElement> group_elements = {u};
    LelantusPrimitives::generate_challenge(group_elements, c);
    proof_out.P1 = P0 - c * P;
    proof_out.T1 = T0 - c * T;
}

}//namespace lelantus