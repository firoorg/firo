namespace sigma {

template<class Exponent, class GroupElement>
R1ProofGenerator<Exponent,GroupElement>::R1ProofGenerator(
        const GroupElement& g,
        const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_gens,
        const std::vector<Exponent>& b,
        const Exponent& r,
        int n ,
        int m)
    : g_(g)
    , h_(h_gens)
    , b_(b)
    , r(r)
    , n_(n)
    , m_(m){
    SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_,b_,r,B_Commit);
}

template<class Exponent, class GroupElement>
void R1ProofGenerator<Exponent,GroupElement>::proof(
        R1Proof<Exponent, GroupElement>& proof_out) const {
    std::vector<Exponent> a;
    proof(a, proof_out);

}

template<class Exponent, class GroupElement>
void R1ProofGenerator<Exponent,GroupElement>::proof(
        std::vector<Exponent>& a,
        R1Proof<Exponent, GroupElement>& proof_out) const {
    Exponent rA, rC, rD;
    rA.randomize();
    rC.randomize();
    rD.randomize();
    a.resize(n_ * m_);
    for(int j = 0; j < m_; ++j){
        for(int i = 1; i < n_; ++i){
            a[j * n_ + i].randomize();
            a[j * n_] -= a[j * n_ + i];
        }
    }
    //compute A
    GroupElement A;
    SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, a, rA, A);
    proof_out.A_ = A;
    //compute C
    std::vector<Exponent> c;
    c.resize(n_ * m_);
    for(int i = 0; i < n_ * m_; ++i) {
        c[i] = (a[i] * (Exponent(uint64_t(1)) - (Exponent(uint64_t(2)) * b_[i])));
    }
    GroupElement C;
    SigmaPrimitives<Exponent, GroupElement>::commit(g_,h_, c, rC, C);
    proof_out.C_ = C;
    //compute D
    std::vector<Exponent> d;
    d.resize(n_ * m_);
    for(int i = 0; i < n_ * m_; i++) {
        d[i] = ((a[i].square()).negate());
    }
    GroupElement D;
    SigmaPrimitives<Exponent, GroupElement>::commit(g_,h_, d, rD, D);
    Exponent x;
    proof_out.D_ = D;
    SigmaPrimitives<Exponent, GroupElement>::get_x(A, C, D,x);
    x_ = x;
    //f
    std::vector<Exponent> f;
    f.reserve(m_ * (n_ - 1));
    for(int j = 0; j < m_; j++){
        for(int i = 1; i < n_; i++)
        f.emplace_back(b_[(j * n_) + i] * x + a[(j * n_) + i]);
    }
    proof_out.f_ =  f;
    //zA
    Exponent zA = r * x + rA;
    proof_out.ZA_ = zA;
    Exponent zC = rC * x + rD;
    proof_out.ZC_ = zC;
}

} //namespace sigma