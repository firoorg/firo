#include "lelantus_verifier.h"

namespace lelantus {

LelantusVerifier::LelantusVerifier(const Params* p) : params(p) {
}

bool LelantusVerifier::verify(
        const std::vector<PublicCoin>& anonymity_set,
        const std::vector<Scalar>& Sin,
        const Scalar& Vin,
        const Scalar& Vout,
        const Scalar f,
        const std::vector<PublicCoin>& Cout,
        const LelantusProof& proof) {
    Scalar x, zV, zR;
    if(!(verify_sigma(anonymity_set, Sin, Vin, Vout, f, Cout, proof.sigma_proofs, x, zV, zR) &&
         verify_rangeproof(Cout, proof.bulletproofs) &&
         verify_schnorrproof(x, zV, zR, Vin, Vout, f, Cout, proof)))
        return false;
    return true;
}

bool LelantusVerifier::verify_sigma(
        const std::vector<PublicCoin>& anonymity_set,
        const std::vector<Scalar>& Sin,
        const Scalar& Vin,
        const Scalar& Vout,
        const Scalar f,
        const std::vector<PublicCoin>& Cout,
        const std::vector<SigmaPlusProof<Scalar, GroupElement>> &sigma_proofs,
        Scalar& x,
        Scalar& zV,
        Scalar& zR) {


    LelantusPrimitives<Scalar, GroupElement>::generate_Lelantus_challange(sigma_proofs, x);
    SigmaPlusVerifier<Scalar, GroupElement> sigmaVerifier(params->get_g(), params->get_sigma_h(), params->get_sigma_n(),
                                                          params->get_sigma_m());

    std::vector<GroupElement> C_;
    for (std::size_t i = 0; i < sigma_proofs.size(); ++i) {
        C_.reserve(anonymity_set.size());
        for (std::size_t j = 0; j < anonymity_set.size(); ++j)
            C_.emplace_back(anonymity_set[j].getValue());
        zV += sigma_proofs[i].zV_;
        zR += sigma_proofs[i].zR_;
    }

    if (!sigmaVerifier.batchverify(C_, x, Sin, sigma_proofs))
        return false;
    return true;
}

bool LelantusVerifier::verify_rangeproof(
        const std::vector<PublicCoin>& Cout,
        const RangeProof<Scalar, GroupElement>& bulletproofs) {

    std::size_t n = params->get_bulletproofs_n();
    std::size_t m = Cout.size();

    while (m & (m - 1))
        m++;

    std::vector<GroupElement> g_, h_;
    g_.reserve(n * m);
    h_.reserve(n * m);
    for (std::size_t i = 0; i < n * m; ++i) {
        g_.push_back(params->get_bulletproofs_g()[i]);
        h_.push_back(params->get_bulletproofs_h()[i]);
    }
    std::vector<GroupElement> V;
    V.reserve(m);
    for (std::size_t i = 0; i < Cout.size(); ++i)
        V.push_back(Cout[i].getValue());

    for (std::size_t i = Cout.size(); i < m; ++i)
        V.push_back(GroupElement());

    RangeVerifier <Scalar, GroupElement> rangeVerifier(params->get_h0(), params->get_h1(), params->get_g(), g_, h_, n);
    if (!rangeVerifier.verify_batch(V, bulletproofs))
        return false;
    return true;
}

bool LelantusVerifier::verify_schnorrproof(
        const Scalar& x,
        const Scalar& zV,
        const Scalar& zR,
        const Scalar& Vin,
        const Scalar& Vout,
        const Scalar f,
        const std::vector<PublicCoin>& Cout,
        const LelantusProof& proof) {
    GroupElement A;
    for (std::size_t i = 0; i < Cout.size(); ++i)
        A += Cout[i].getValue();
    if(Cout.size() > 0)
        A *= x.exponent(params->get_sigma_m());
    A += params->get_h0() * ((Vout + f) * x.exponent(params->get_sigma_m()));

    GroupElement B = (params->get_h0() * (Vin * x.exponent(params->get_sigma_m())))
                     + LelantusPrimitives<Scalar, GroupElement>::double_commit(params->get_g(), uint64_t(0), params->get_h0(), zV, params->get_h1(), zR);
    GroupElement Comm;
    for (std::size_t t = 0; t < proof.sigma_proofs.size(); ++t)
    {
        GroupElement Comm_t;
        const std::vector<GroupElement>& Qk = proof.sigma_proofs[t].Qk;
        Scalar x_k(uint64_t(1));
        for (std::size_t k = 0; k < Qk.size(); ++k)
        {
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