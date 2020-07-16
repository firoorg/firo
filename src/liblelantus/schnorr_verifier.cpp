#include "schnorr_verifier.h"

namespace lelantus {
    
SchnorrVerifier::SchnorrVerifier(const GroupElement& g, const GroupElement& h):
        g_(g), h_(h) {
}

bool SchnorrVerifier::verify(
        const GroupElement& y,
        const SchnorrProof& proof){

    const GroupElement& u = proof.u;
    Scalar c;
    std::vector<GroupElement> group_elements = {u};
    LelantusPrimitives::generate_challenge(group_elements, c);
    const Scalar P1 = proof.P1;
    const Scalar T1 = proof.T1;

    if(!(u.isMember() && y.isMember() && P1.isMember() && T1.isMember()) ||
        u.isInfinity() || y.isInfinity() || P1.isZero() || T1.isZero())
        return false;

    GroupElement right = y * c + g_ * P1 + h_ * T1;
    if(u == right) {
        return true;
    }

    return false;
}

}//namespace lelantus