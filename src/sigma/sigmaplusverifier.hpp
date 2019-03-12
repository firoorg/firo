namespace sigma{
template<class Exponent, class GroupElement>
SigmaPlusVerifier<Exponent, GroupElement>::SigmaPlusVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        int n,
        int m)
    : g_(g)
    , h_(h_gens)
    , n(n)
    , m(m){
}

template<class Exponent, class GroupElement>
bool  SigmaPlusVerifier<Exponent, GroupElement>::verify(
        const std::vector<GroupElement>& commits,
        const SigmaPlusProof<Exponent, GroupElement>& proof) const {

    R1ProofVerifier<Exponent, GroupElement> r1ProofVerifier(g_, h_, proof.B_, n, m);
    std::vector<Exponent> f;
    const R1Proof<Exponent, GroupElement>& r1Proof = proof.r1Proof_;
    if (!r1ProofVerifier.verify(r1Proof, f))
        return false;
    if (!(proof.B_).isMember())
        return false;

    const std::vector <GroupElement>& Gk = proof.Gk_;
    for (int k = 0; k < m; ++k) {
        if (!Gk[k].isMember())
            return false;
    }

    if(!proof.z_.isMember())
        return false;
    int N = commits.size();
    std::vector<Exponent> f_i_;
    f_i_.reserve(N);
    for(int i = 0; i < N; ++i){
        std::vector<uint64_t> I = SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(i, n, m);
        Exponent f_i(uint64_t(1));
        for(int j = 0; j < m; ++j){
            f_i *= f[j*n + I[j]];
        }
        f_i_.emplace_back(f_i);
    }
    GroupElement t1;
    const int window_size = 7;
    zcoin_common::GeneratorVector<Exponent, GroupElement> c_(commits, window_size);
    c_.get_vector_multiple(f_i_, t1);
    GroupElement t2;
    Exponent x = r1ProofVerifier.x_;
    Exponent x_k(uint64_t(1));
    for(int k = 0; k < m; ++k){
        t2 += (Gk[k] * (x_k.negate()));
        x_k *= x;
    }

    GroupElement left(t1 + t2);
    if(left != SigmaPrimitives<Exponent, GroupElement>::commit(g_, Exponent(uint64_t(0)), h_.get_g(0), proof.z_))
        return false;

    return true;
}

} //namespace sigma