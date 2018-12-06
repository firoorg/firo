namespace nextgen{
template<class Exponent, class GroupElement>
SigmaPlusVerifier<Exponent, GroupElement>::SigmaPlusVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        uint64_t n,
        uint64_t m)
    : g_(g)
    , h_(h_gens)
    , n(n)
    , m(m){
}

template<class Exponent, class GroupElement>
bool  SigmaPlusVerifier<Exponent, GroupElement>::verify(
        const std::vector<GroupElement>& commits,
        const SigmaPlusProof<Exponent, GroupElement>& proof) const {
    Exponent x;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A_, proof.C_, proof.D_,x);
    return verify(commits, x, proof);
}

template<class Exponent, class GroupElement>
bool  SigmaPlusVerifier<Exponent, GroupElement>::verify(
        const std::vector<GroupElement>& commits,
        const Exponent& x,
        const SigmaPlusProof<Exponent, GroupElement>& proof) const {

    if(!(proof.A_.isMember() &&
         proof.B_.isMember()  &&
         proof.C_.isMember() &&
         proof.D_.isMember()))
        return false;

    for(int i = 0; i < proof.f_.size(); i++)
        if(!proof.f_[i].isMember())
            return false;
    std::vector<Exponent> f_;
    f_.reserve(n * m);
    for(int j = 0; j < m; ++j){
        f_.push_back(Exponent(uint64_t(0)));
        Exponent temp;
        int k = n - 1;
        for(int i = 0; i < k; ++i){
            temp += proof.f_[j * k + i];
            f_.emplace_back(proof.f_[j * k + i]);
        }
        f_[j * n] = x - temp;
    }

    GroupElement one;
    NextGenPrimitives<Exponent, GroupElement>::commit(g_, h_, f_, proof.ZA_, one);
    if((proof.B_ * x + proof.A_) != one)
        return false;

    std::vector<Exponent> f_prime;
    f_prime.reserve(f_.size());
    for(int i = 0; i < f_.size(); i++)
        f_prime.emplace_back(f_[i] * (x - f_[i]));
    GroupElement two;
    NextGenPrimitives<Exponent, GroupElement>::commit(g_, h_, f_prime, proof.ZC_, two);
    if((proof.C_ * x + proof.D_) != two)
        return false;

    if (!(proof.B_).isMember())
        return false;

    const std::vector <GroupElement>& Gk = proof.Gk_;
    const std::vector <GroupElement>& Qk = proof.Qk;
    for (int k = 0; k < m; ++k) {
        if (!(Gk[k].isMember() && Qk[k].isMember()))
            return false;
    }
    int N = commits.size();
    std::vector<Exponent> f_i_;
    f_i_.reserve(N);
    for(int i = 0; i < N; ++i){
        std::vector<uint64_t> I = NextGenPrimitives<Exponent, GroupElement>::convert_to_nal(i, n, m);
        Exponent f_i(uint64_t(1));
        for(int j = 0; j < m; ++j){
            f_i *= f_[j*n + I[j]];
        }
        f_i_.emplace_back(f_i);
    }
    GroupElement t1;
    const int window_size = 7;
    zcoin_common::GeneratorVector<Exponent, GroupElement> c_(commits, window_size);
    c_.get_vector_multiple(f_i_, t1);
    GroupElement t2;
    Exponent x_k(uint64_t(1));
    std::vector<Exponent> x_k_;
    for(int k = 0; k < m; ++k){
        t2 += ((Gk[k] + Qk[k] )* (x_k.negate()));
        x_k *= x;
    }

    GroupElement left(t1 + t2);
    if(left != NextGenPrimitives<Exponent, GroupElement>::double_commit(g_, Exponent(uint64_t(0)), h_.get_g(0), proof.zV_, h_.get_g(1), proof.zR_))
        return false;

    return true;
}

} //namespace nextgen