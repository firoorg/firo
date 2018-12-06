#include "NextGenVerifier.h"

namespace nextgen {

NextGenVerifier::NextGenVerifier(const Params* p) : params(p) {
}

bool NextGenVerifier::verify(
        const std::vector<PublicCoin>& c,
        const std::vector<Scalar>& Sin,
        const Scalar& Vin,
        const Scalar& Vout,
        const Scalar f,
        const std::vector<PublicCoin>& Cout,
        const NextGenProof& proof){
    const std::vector<SigmaPlusProof<Scalar, GroupElement>>& sigma_proofs = proof.sigma_proofs;
    Scalar x;
    NextGenPrimitives<Scalar, GroupElement>::get_x(sigma_proofs, x);
    SigmaPlusVerifier<Scalar, GroupElement> sigmaVerifier(params->get_g(), params->get_h(), params->get_n(), params->get_m());
    Scalar zV, zR;
    for(int i = 0; i < sigma_proofs.size(); ++i){
        GroupElement gs = params->get_g() * Sin[i].negate();
        std::vector<GroupElement> C_;
        C_.reserve(c.size());
        for(int j = 0; j < c.size(); ++j)
            C_.emplace_back(c[j].getValue() + gs);
        if(!sigmaVerifier.verify(C_, x, sigma_proofs[i]))
            return false;
        zV += sigma_proofs[i].zV_;
        zR += sigma_proofs[i].zR_;
    }

    GroupElement A;

    for(int i = 0; i < Cout.size(); ++i)
        A += Cout[i].getValue();
    if(Cout.size() > 0)
        A *= x.exponent(params->get_m());
    A += params->get_h0() * ((Vout + f) * x.exponent(params->get_m()));

    GroupElement B = (params->get_h0() * (Vin * x.exponent(params->get_m())))
                    + NextGenPrimitives<Scalar, GroupElement>::double_commit(params->get_g(), uint64_t(0), params->get_h0(), zV, params->get_h1(), zR);
    GroupElement Comm;
    for(int t = 0; t < sigma_proofs.size(); ++t){
        GroupElement Comm_t;
        const std::vector<GroupElement>& Qk = sigma_proofs[t].Qk;
        Scalar x_k(uint64_t(1));
        for(int k = 0; k < Qk.size(); ++k) {
            Comm_t += (Qk[k]) * x_k;
            x_k *= x;
        }
        Comm += Comm_t;
    }
    B += Comm;
    SchnorrVerifier<Scalar, GroupElement> schnorrVerifier(params->get_g(), params->get_h1());
    const SchnorrProof<Scalar, GroupElement>& schnorrProof = proof.schnorrProof;
    GroupElement Y = A + B * (Scalar(uint64_t(1)).negate());
    if(!schnorrVerifier.verify(Y, schnorrProof))
        return false;

    return true;
}

}//namespace nextgen