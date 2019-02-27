#include "LelantusVerifier.h"

namespace lelantus {

LelantusVerifier::LelantusVerifier(const Params* p) : params(p) {
}

bool LelantusVerifier::verify(
        const std::vector<PublicCoin>& c,
        const std::vector<Scalar>& Sin,
        const Scalar& Vin,
        const Scalar& Vout,
        const Scalar f,
        const std::vector<PublicCoin>& Cout,
        const LelantusProof& proof){
    //sigma verification
    const std::vector<SigmaPlusProof<Scalar, GroupElement>>& sigma_proofs = proof.sigma_proofs;
    Scalar x;
    LelantusPrimitives<Scalar, GroupElement>::get_x(sigma_proofs, x);
    SigmaPlusVerifier<Scalar, GroupElement> sigmaVerifier(params->get_g(), params->get_h(), params->get_n(), params->get_m());
    Scalar zV, zR;

    std::vector<GroupElement> C_;
    for(int i = 0; i < sigma_proofs.size(); ++i){
        C_.reserve(c.size());
        for(int j = 0; j < c.size(); ++j)
            C_.emplace_back(c[j].getValue());
        zV += sigma_proofs[i].zV_;
        zR += sigma_proofs[i].zR_;
    }

    if(!sigmaVerifier.batchverify(C_, x, Sin, sigma_proofs))
        return false;

    //range proof verification
    int n = params->get_bulletproofs_n();
    int m = Cout.size();
    std::vector<GroupElement> g_, h_;
    g_.reserve(n * m);
    h_.reserve(n * m);
    for(int i = 0; i < n * m; ++i ){
        g_.push_back(params->get_bulletproofs_g()[i]);
        h_.push_back(params->get_bulletproofs_h()[i]);
    }
    std::vector<GroupElement> V;
    V.reserve(Cout.size());
    for(int i = 0; i < Cout.size(); ++i)
        V.push_back(Cout[i].getValue());

    RangeVerifier<Scalar, GroupElement> rangeVerifier(params->get_h0(), params->get_h1(), params->get_g(), g_, h_, n);
    if(!rangeVerifier.verify_batch(V, proof.bulletproofs))
        return false;

    //schnorr proof verification
    GroupElement A;
    for(int i = 0; i < Cout.size(); ++i)
        A += Cout[i].getValue();
    if(Cout.size() > 0)
        A *= x.exponent(params->get_m());
    A += params->get_h0() * ((Vout + f) * x.exponent(params->get_m()));

    GroupElement B = (params->get_h0() * (Vin * x.exponent(params->get_m())))
                    + LelantusPrimitives<Scalar, GroupElement>::double_commit(params->get_g(), uint64_t(0), params->get_h0(), zV, params->get_h1(), zR);
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

}//namespace lelantus