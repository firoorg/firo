namespace lelantus {

template<class Exponent, class GroupElement>
SigmaPlusProver<Exponent, GroupElement>::SigmaPlusProver(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        uint64_t n,
        uint64_t m)
    : g_(g)
    , h_(h_gens)
    , n_(n)
    , m_(m) {
}

template<class Exponent, class GroupElement>
void SigmaPlusProver<Exponent, GroupElement>::proof(
        const std::vector<GroupElement>& commits,
        int l,
        const Exponent& v,
        const Exponent& r,
        SigmaPlusProof<Exponent, GroupElement>& proof_out) {
    Exponent rA, rB, rC, rD;
    rA.randomize();
    rB.randomize();
    rC.randomize();
    rD.randomize();
    std::vector <Exponent> sigma;
    std::vector <Exponent> Tk, Pk, Yk;
    Tk.resize(m_);
    Pk.resize(m_);
    Yk.resize(m_);
    std::vector<Exponent> a;
    a.resize(n_ * m_);
    sigma_commit(commits, l, rA, rB, rC, rD, a, Tk, Pk, Yk, sigma, proof_out);
    Exponent x;
    LelantusPrimitives<Exponent, GroupElement>::get_x(proof_out.A_, proof_out.C_, proof_out.D_,x);
    sigma_response(sigma, a, rA, rB, rC, rD, v, r, Tk, Pk, x, proof_out);
}

template<class Exponent, class GroupElement>
void SigmaPlusProver<Exponent, GroupElement>::sigma_commit(
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
        SigmaPlusProof<Exponent, GroupElement>& proof_out) {
    int N = commits.size();
    LelantusPrimitives<Exponent, GroupElement>::convert_to_sigma(l, n_, m_, sigma);
    for (int k = 0; k < m_; ++k)
    {
        Tk[k].randomize();
        Pk[k].randomize();
        Yk[k].randomize();
    }
    LelantusPrimitives<Exponent, GroupElement>::commit(g_, h_, sigma, rB, proof_out.B_);

    for (int j = 0; j < m_; ++j)
    {
        for (int i = 1; i < n_; ++i)
        {
            a[j * n_ + i].randomize();
            a[j * n_] -= a[j * n_ + i];
        }
    }
    //compute A
    LelantusPrimitives<Exponent, GroupElement>::commit(g_, h_, a, rA, proof_out.A_);
    //compute C
    std::vector<Exponent> c;
    c.resize(n_ * m_);
    for (int i = 0; i < n_ * m_; ++i)
    {
        c[i] = (a[i] * (Exponent(uint64_t(1)) - (Exponent(uint64_t(2)) * sigma[i])));
    }
    LelantusPrimitives<Exponent, GroupElement>::commit(g_,h_, c, rC, proof_out.C_);
    //compute D
    std::vector<Exponent> d;
    d.resize(n_ * m_);
    for (int i = 0; i < n_ * m_; i++)
    {
        d[i] = ((a[i].square()).negate());
    }
    LelantusPrimitives<Exponent, GroupElement>::commit(g_,h_, d, rD, proof_out.D_);

    std::vector <std::vector<Exponent>> P_i_k;
    P_i_k.resize(N);
    for (int i = 0; i < commits.size(); ++i)
    {
        std::vector <Exponent>& coefficients = P_i_k[i];
        std::vector<uint64_t> I = LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(i, n_, m_);
        coefficients.push_back(sigma[I[0]]);
        coefficients.push_back(a[I[0]]);
        for (int j = 1; j < m_; ++j) {
            LelantusPrimitives<Exponent, GroupElement>::new_factor(sigma[j * n_ + I[j]], a[j * n_ + I[j]], coefficients);
        }
        std::reverse(coefficients.begin(), coefficients.end());
    }

    proof_out.Gk_.reserve(m_);
    proof_out.Qk.reserve(m_);
    const int window_size = 7;
    zcoin_common::GeneratorVector <Exponent, GroupElement> c_(commits, window_size);
    for (int k = 0; k < m_; ++k)
    {
        std::vector <Exponent> P_i;
        P_i.reserve(N);
        for (int i = 0; i < N; ++i){
            P_i.emplace_back(P_i_k[i][k]);
        }
        GroupElement c_k;
        c_.get_vector_multiple(P_i, c_k);
        proof_out.Gk_.emplace_back(c_k + h_.get_g(1) * Yk[k].negate());
        proof_out.Qk.emplace_back(LelantusPrimitives<Exponent, GroupElement>::double_commit(g_, Exponent(uint64_t(0)), h_.get_g(0), Pk[k], h_.get_g(1), Tk[k]) + h_.get_g(1) * Yk[k]);

    }
}

template<class Exponent, class GroupElement>
void SigmaPlusProver<Exponent, GroupElement>::sigma_response(
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
        SigmaPlusProof<Exponent, GroupElement>& proof_out) {

    //f
    proof_out.f_ .reserve(m_ * (n_ - 1));
    for (int j = 0; j < m_; j++)
    {
        for (int i = 1; i < n_; i++)
            proof_out.f_.emplace_back(sigma[(j * n_) + i] * x + a[(j * n_) + i]);
    }
    //zA, zC
    proof_out.ZA_ =  rB * x + rA;
    proof_out.ZC_ = rC * x + rD;

    //computing z
    proof_out.zV_ = v * x.exponent(uint64_t(m_));
    proof_out.zR_ = r * x.exponent(uint64_t(m_));
    Exponent sumV, sumR;
    Exponent x_k(uint64_t(1));
    for (int k = 0; k < m_; ++k) {
        sumV += (Pk[k] * x_k);
        sumR += (Tk[k] * x_k);
        x_k *= x;
    }
    proof_out.zV_ -= sumV;
    proof_out.zR_ -= sumR;
}

}//namespace lelantus