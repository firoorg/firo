#include "lelantus_verifier.h"

namespace lelantus {

LelantusVerifier::LelantusVerifier(const Params* p) : params(p) {
}

bool LelantusVerifier::verify(
        const std::vector<std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<Scalar>>& Sin,
        const Scalar& Vin,
        const Scalar& Vout,
        const Scalar f,
        const std::vector<PublicCoin>& Cout,
        const LelantusProof& proof) {
    Scalar x, zV, zR;
    if(!(verify_sigma(anonymity_sets, Sin, Vin, Vout, f, Cout, proof.sigma_proofs, x, zV, zR) &&
         verify_rangeproof(Cout, proof.bulletproofs) &&
         verify_schnorrproof(x, zV, zR, Vin, Vout, f, Cout, proof)))
        return false;
    return true;
}

bool LelantusVerifier::verify_sigma(
        const std::vector<std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<Scalar>>& Sin,
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

    if(Sin.size() != anonymity_sets.size())
        throw ZerocoinException("Number of anonymity sets and number of vectors containing serial numbers must be equal");

    int t = 0;
    for(std::size_t k = 0; k < Sin.size(); k++) {

        std::vector<GroupElement> C_;
        std::vector<SigmaPlusProof<Scalar, GroupElement>> sigma_proofs_k;
        for (std::size_t i = 0; i < Sin[k].size(); ++i, ++t) {
            C_.reserve(anonymity_sets[k].size());
            for (std::size_t j = 0; j < anonymity_sets[k].size(); ++j)
                C_.emplace_back(anonymity_sets[k][j].getValue());
            zV += sigma_proofs[t].zV_;
            zR += sigma_proofs[t].zR_;
            sigma_proofs_k.emplace_back(sigma_proofs[t]);
        }

        if (!sigmaVerifier.batchverify(C_, x, Sin[k], sigma_proofs_k))
            return false;
    }
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

    RangeVerifier <Scalar, GroupElement> rangeVerifier(params->get_h1(), params->get_h0(), params->get_g(), g_, h_, n);
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
    A += params->get_h1() * ((Vout + f) * x.exponent(params->get_sigma_m()));

    GroupElement B = (params->get_h1() * (Vin * x.exponent(params->get_sigma_m())))
                     + LelantusPrimitives<Scalar, GroupElement>::double_commit(params->get_g(), uint64_t(0), params->get_h1(), zV, params->get_h0(), zR);
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
    SchnorrVerifier<Scalar, GroupElement> schnorrVerifier(params->get_g(), params->get_h0());
    const SchnorrProof<Scalar, GroupElement>& schnorrProof = proof.schnorrProof;
    GroupElement Y = A + B * (Scalar(uint64_t(1)).negate());
    if(!schnorrVerifier.verify(Y, schnorrProof))
        return false;
    return true;
}

}//namespace lelantus