#include "NextGenProver.h"
namespace nextgen{
NextGenProver::NextGenProver(const Params* p) : params(p) {

}

#include <iostream>
void NextGenProver::proof(
        const std::vector<PublicCoin>& c,
        const Scalar& Vin,
        const std::vector<PrivateCoin>& Cin,
        const std::vector<uint64_t>& indexes,
        const Scalar& Vout,
        const std::vector<PrivateCoin>& Cout,
        const Scalar& f,
        NextGenProof& proof_out) {
    Scalar input = Vin;
    for(int i = 0; i < Cin.size(); ++i)
        input += Cin[i].getPublicCoin().get_v();
    Scalar out = Vout;
    for(int i = 0; i < Cout.size(); ++i)
        out += Cout[i].getPublicCoin().get_v();
    out += f;

    if(input != out)
        throw "Input and output are not equal";
    Scalar x;
    generate_sigma_proofs(c, Cin, indexes, x, proof_out.sigma_proofs);
    generate_bulletproofs(Cout, proof_out.bulletproofs);
    Scalar X_;
    Scalar So;
    Scalar Ro;
    for(int i = 0; i < Cout.size(); ++i){
        So += Cout[i].getSerialNumber();
        Ro += Cout[i].getRandomness();
    }
    X_ = So * x.exponent(params->get_m());
    Scalar Y_;
    Scalar Ri;
    for(int i = 0; i < Cin.size(); ++i){
        Ri += Cin[i].getRandomness();
    }
    Y_ = Ro - Ri;
    Y_*= x.exponent(params->get_m());
    SchnorrProver<Scalar, GroupElement> schnorrProver(params->get_g(), params->get_h1());
    schnorrProver.proof(X_, Y_, proof_out.schnorrProof);

}

void NextGenProver::generate_sigma_proofs(
        const std::vector<PublicCoin>& c,
        const std::vector<PrivateCoin>& Cin,
        const std::vector<uint64_t>& indexes,
        Scalar& x,
        std::vector<SigmaPlusProof<Scalar, GroupElement>>& sigma_proofs){
    SigmaPlusProver<Scalar,GroupElement> sigmaProver(params->get_g(), params->get_h(), params->get_n(), params->get_m());
    sigma_proofs.resize(Cin.size());
    int N = Cin.size();
    std::vector<Scalar> rA, rB, rC, rD;
    rA.resize(N);
    rB.resize(N);
    rC.resize(N);
    rD.resize(N);
    std::vector<std::vector<Scalar>> sigma;
    sigma.resize(N);
    std::vector<std::vector<Scalar>> Tk, Pk;
    Tk.resize(N);
    Pk.resize(N);
    std::vector<std::vector<Scalar>> a;
    a.resize(N);
    for(int i = 0; i < N; ++i){
        GroupElement gs = (params->get_g() * Cin[i].getSerialNumber().negate());
        std::vector<GroupElement> C_;
        C_.reserve(c.size());
        for(int j = 0; j < c.size(); ++j)
            C_.emplace_back(c[j].getValue() + gs);

        rA[i].randomize();
        rB[i].randomize();
        rC[i].randomize();
        rD[i].randomize();
        Tk[i].resize(params->get_m());
        Pk[i].resize(params->get_m());
        a[i].resize(params->get_n() * params->get_m());
        sigmaProver.sigma_commit(C_, indexes[i], rA[i], rB[i], rC[i], rD[i], a[i], Tk[i], Pk[i], sigma[i], sigma_proofs[i]);
    }
    NextGenPrimitives<Scalar, GroupElement>::get_x(sigma_proofs, x);
    for(int i = 0; i < N; ++i){
        const Scalar& v = Cin[i].getPublicCoin().get_v();
        const Scalar& r = Cin[i].getRandomness();
        sigmaProver.sigma_response(sigma[i], a[i], rA[i], rB[i], rC[i], rD[i], v, r, Tk[i], Pk[i], x, sigma_proofs[i]);
    }
}

void NextGenProver::generate_bulletproofs(
        const std::vector <PrivateCoin>& Cout,
        RangeProof<Scalar, GroupElement>& bulletproofs){
    std::vector<secp_primitives::Scalar> v_s, serials, randoms;
    int n = params->get_bulletproofs_n();
    int m = Cout.size();
    v_s.reserve(m);
    serials.reserve(m);
    randoms.reserve(m);
    for(int i = 0; i < m; ++i){
        v_s.push_back(Cout[i].getPublicCoin().get_v());
        serials.push_back(Cout[i].getSerialNumber());
        randoms.push_back(Cout[i].getRandomness());
    }

    std::vector<GroupElement> g_, h_;
    g_.reserve(n * m);
    h_.reserve(n * m);

    for(int i = 0; i < n * m; ++i ){
        g_.push_back(params->get_bulletproofs_g()[i]);
        h_.push_back(params->get_bulletproofs_h()[i]);
    }

    RangeProver<Scalar, GroupElement> rangeProver(params->get_h0(), params->get_h1(), params->get_g(), g_, h_, n);
    rangeProver.batch_proof(v_s, serials, randoms, bulletproofs);

}

}//namespace nextgen