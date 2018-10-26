namespace sigma{
template<class Exponent, class GroupElement>
SigmaPlusVerifier<Exponent, GroupElement>::SigmaPlusVerifier(const GroupElement& g,
                                     const std::vector<GroupElement>& h_gens)
                                    : g_(g), h_(h_gens){}

template<class Exponent, class GroupElement>
bool  SigmaPlusVerifier<Exponent, GroupElement>::verify(const std::vector<GroupElement>& commits,const SigmaPlusProof<Exponent, GroupElement>& proof) const {
    int n = proof.n_;
    int m = proof.m_;
    R1ProofVerifier<Exponent, GroupElement> r1ProofVerifier(g_, h_, proof.B_, n, m);
    const R1Proof<Exponent, GroupElement>& r1Proof = proof.r1Proof_;
    if (!r1ProofVerifier.verify(r1Proof))
        return false;
    if (!(proof.B_).isMember())
        return false;

    const std::vector <GroupElement>& Gk = proof.Gk_;
    for (int k = 0; k < m; ++k) {
        if (!Gk[k].isMember())
            return false;
    }
    int N = commits.size();
    std::vector <Exponent> exp;
    zcoin_common::GeneratorVector<Exponent, GroupElement> c(commits);
    const std::vector<Exponent>& f = r1Proof.get_f();
    for (int i = 0; i < N; ++i) {
        std::vector<uint64_t> i_ = convert_to_nal(i, n, m);
        Exponent e(uint64_t(1));
        for (int j = 0; j < m; ++j) {
                e *= f[n * (j) + i_[j] ];
//                e *= f[n * (j-1) ];
        }
        exp.push_back(e);
    }
    GroupElement t1;
    c.get_vector_multiple(exp, t1);

    GroupElement t2;
    Exponent x = r1ProofVerifier.x_;
    for(int k = 0; k < m; ++k){
        t2 += (Gk[k] * (x.negate()).exponent(uint64_t(k)));
    }

    GroupElement left(t1 + t2);
    if(!(left == commit(g_, Exponent(uint64_t(0)), h_.get_g(0), proof.z_)))
        return false;

    return true;
}

} //namespace sigma