namespace sigma {

template<class Exponent, class GroupElement>
R1ProofGenerator<Exponent,GroupElement>::R1ProofGenerator(const GroupElement& g,
                                                           const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_gens,
                                                           const std::vector<Exponent>& b,
                                                           const Exponent& r, int n , int m)
                                                            : g_(g), h_(h_gens),  b_(b), r(r), n_(n), m_(m){
    commit(g_, h_,b_,r,B_Commit);
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
    for(int j = 0; j < m_; ++j){
        Exponent aj0(uint64_t(0));
        a.push_back(Exponent(uint64_t(0)));
        for(int i = 1; i < n_; ++i){
            a.push_back(Exponent(uint64_t(0)));
//            a[j * n_ + i].randomize();
//            aj0 += a[j * n_ + i];
        }
        a[j * n_] = (aj0.negate());
    }
    //compute A
    GroupElement A;
    commit(g_, h_, a, rA, A);
    proof_out.set_A(A);
    //compute C
    std::vector<Exponent> c;
    for(int i = 0; i < n_ * m_; ++i) {
        c.push_back(a[i] * (Exponent(uint64_t(1)) - (Exponent(uint64_t(2)) * b_[i])));
    }
    GroupElement C;
    commit(g_,h_, c, rC, C);
    proof_out.set_C(C);
    //compute D
    std::vector<Exponent> d;
    for(int i = 0; i < n_ * m_; i++) {
        d.push_back((a[i].square()).negate());
    }
    GroupElement D;
    commit(g_,h_, d, rD, D);
    Exponent x(uint64_t(0));
    proof_out.set_D(D);
//    get_x(A, C, D,x);
    x_ = x;
    //f
    std::vector<Exponent> f;
    for(int i = 0; i < n_ * m_; i++){
        f.push_back(b_[i] * x + a[i]);
    }
    proof_out.set_f(f);
    //zA
    Exponent zA = r * x + rA;
    proof_out.set_zA(zA);
    Exponent zC = rC * x + rD;
    proof_out.set_zC(zC);
}

} //namespace sigma