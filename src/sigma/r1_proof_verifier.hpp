namespace sigma {

template<class Exponent, class GroupElement>
R1ProofVerifier<Exponent,GroupElement>::R1ProofVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        const GroupElement& B,
        int n ,
        int m)
    : g_(g)
    , h_(h_gens)
    , B_Commit(B)
    , n_(n)
    , m_(m){
}

template<class Exponent, class GroupElement>
bool R1ProofVerifier<Exponent,GroupElement>::verify(
        const R1Proof<Exponent, GroupElement>& proof_) const {
    std::vector<Exponent> f_;
    return verify(proof_, f_);
}

template<class Exponent, class GroupElement>
bool R1ProofVerifier<Exponent,GroupElement>::verify(
        const R1Proof<Exponent, GroupElement>& proof_,
        std::vector<Exponent>& f_) const{

    if(!(proof_.A_.isMember() &&
         B_Commit.isMember()  &&
         proof_.C_.isMember() &&
         proof_.D_.isMember()))
        return false;
    const std::vector<Exponent>& f = proof_.f_;
    for (std::size_t i = 0; i < f.size(); i++) {
        if(!f[i].isMember())
            return false;
    }

    if(!(proof_.ZA_.isMember() &&
         proof_.ZC_.isMember()))
        return false;

    Exponent x;
    SigmaPrimitives<Exponent, GroupElement>::get_x(proof_.A_,proof_.C_, proof_.D_, x);
    x_ = x;
    f_.reserve(n_ * m_);
    for(int j = 0; j < m_; ++j){
        f_.push_back(Exponent(uint64_t(0)));
        Exponent temp;
        int k = n_ - 1;
        for(int i = 0; i < k; ++i){
            temp += f[j * k + i];
            f_.emplace_back(f[j * k + i]);
        }
        f_[j * n_] = x - temp;
    }

    GroupElement one;
    SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, f_, proof_.ZA_, one);
    if((B_Commit * x + proof_.A_) != one)
        return false;

    std::vector<Exponent> f_prime;
    f_prime.reserve(f_.size());
    for (std::size_t i = 0; i < f_.size(); i++)
        f_prime.emplace_back(f_[i] * (x - f_[i]));
    GroupElement two;
    SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, f_prime, proof_.ZC_, two);
    if((proof_.C_ * x + proof_.D_) != two)
        return false;

    return true;
}

} // namespace sigma
