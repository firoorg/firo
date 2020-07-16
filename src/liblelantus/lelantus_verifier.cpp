#include "lelantus_verifier.h"

#include "chainparams.h"

namespace lelantus {

LelantusVerifier::LelantusVerifier(const Params* p) : params(p) {
}

bool LelantusVerifier::verify(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<Scalar>& serialNumbers,
        const std::vector<uint32_t>& groupIds,
        const Scalar& Vin,
        const Scalar& Vout,
        const Scalar f,
        const std::vector<PublicCoin>& Cout,
        const LelantusProof& proof) {
    std::vector<std::vector<PublicCoin>> vAnonymity_sets;
    std::vector<std::vector<Scalar>> vSin;
    vAnonymity_sets.reserve(anonymity_sets.size());
    vSin.resize(anonymity_sets.size());

    size_t i = 0;
    auto itr = vSin.begin();
    for(const auto& set : anonymity_sets) {
        vAnonymity_sets.emplace_back(set.second);

        while (i < groupIds.size() && groupIds[i] == set.first) {
            itr->push_back(serialNumbers[i++]);
        }
        itr++;
    }

    Scalar x, zV, zR;
    if(!(verify_sigma(vAnonymity_sets, vSin, proof.sigma_proofs, x, zV, zR) &&
         verify_rangeproof(Cout, proof.bulletproofs) &&
         verify_schnorrproof(x, zV, zR, Vin, Vout, f, Cout, proof)))
        return false;
    return true;
}

bool LelantusVerifier::verify_sigma(
        const std::vector<std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<Scalar>>& Sin,
        const std::vector<SigmaExtendedProof> &sigma_proofs,
        Scalar& x,
        Scalar& zV,
        Scalar& zR) {


    LelantusPrimitives::generate_Lelantus_challange(sigma_proofs, x);
    SigmaExtendedVerifier sigmaVerifier(params->get_g(), params->get_sigma_h(), params->get_sigma_n(),
                                                          params->get_sigma_m());

    if(Sin.size() != anonymity_sets.size())
        throw std::invalid_argument("Number of anonymity sets and number of vectors containing serial numbers must be equal");

    int t = 0;
    for(std::size_t k = 0; k < Sin.size(); k++) {

        std::vector<GroupElement> C_;
        C_.reserve(anonymity_sets[k].size());
        for (std::size_t j = 0; j < anonymity_sets[k].size(); ++j)
            C_.emplace_back(anonymity_sets[k][j].getValue());

        std::vector<SigmaExtendedProof> sigma_proofs_k;
        for (std::size_t i = 0; i < Sin[k].size(); ++i, ++t) {
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
        const RangeProof& bulletproofs) {

    std::size_t n = params->get_bulletproofs_n();
    std::size_t m = Cout.size();

    while (m & (m - 1))
        m++;

    std::vector<GroupElement> g_, h_;
    g_.reserve(n * m);
    h_.reserve(n * m);
    g_.insert(g_.end(), params->get_bulletproofs_g().begin(), params->get_bulletproofs_g().begin() + (n * m));
    h_.insert(h_.end(), params->get_bulletproofs_h().begin(), params->get_bulletproofs_h().begin() + (n * m));

    std::vector<GroupElement> V;
    V.reserve(m);
    for (std::size_t i = 0; i < Cout.size(); ++i)
        V.push_back(Cout[i].getValue() + params->get_h1() * (Scalar(uint64_t(2)).exponent(params->get_bulletproofs_n()) - ::Params().GetConsensus().nMaxValueLelantusMint));

    for (std::size_t i = Cout.size(); i < m; ++i)
        V.push_back(GroupElement());

    RangeVerifier  rangeVerifier(params->get_h1(), params->get_h0(), params->get_g(), g_, h_, n);
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
                     + LelantusPrimitives::double_commit(params->get_g(), uint64_t(0), params->get_h1(), zV, params->get_h0(), zR);

    NthPower x_k(x);
    std::vector<Scalar> x_ks;
    x_ks.reserve(params->get_sigma_m());
    for (int k = 0; k < params->get_sigma_m(); ++k)
    {
        x_ks.emplace_back(x_k.pow);
        x_k.go_next();
    }

    GroupElement Comm;
    for (std::size_t t = 0; t < proof.sigma_proofs.size(); ++t)
    {
        GroupElement Comm_t;
        const std::vector<GroupElement>& Qk = proof.sigma_proofs[t].Qk;
        for (std::size_t k = 0; k < Qk.size(); ++k)
        {
            Comm_t += (Qk[k]) * x_ks[k];
        }
        Comm += Comm_t;
    }
    B += Comm;
    SchnorrVerifier schnorrVerifier(params->get_g(), params->get_h0());
    const SchnorrProof& schnorrProof = proof.schnorrProof;
    GroupElement Y = A + B * (Scalar(uint64_t(1)).negate());
    if(!schnorrVerifier.verify(Y, schnorrProof))
        return false;
    return true;
}

}//namespace lelantus