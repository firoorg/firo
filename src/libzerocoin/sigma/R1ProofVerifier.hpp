namespace sigma {

template<class Exponent, class GroupElement>
R1ProofVerifier<Exponent,GroupElement>::R1ProofVerifier(const GroupElement& g,
                                                        const zcoin_common::GeneratorVector<Exponent, GroupElement>& h_gens,
                                                        const GroupElement& B, int n , int m)
                                                       : g_(g),h_(h_gens), B_Commit(B), n_(n), m_(m){
}

template<class Exponent, class GroupElement>
bool
R1ProofVerifier<Exponent,GroupElement>::verify(const R1Proof<Exponent, GroupElement>& proof_) const{
    if(!proof_.get_A().isMember())
        return false;
    if(!B_Commit.isMember())
        return false;
    if(!proof_.get_C().isMember())
        return false;
    if(!proof_.get_D().isMember())
        return false;
    const std::vector<Exponent>& f = proof_.get_f();
    for(int i = 0; i < f.size(); i++){
        if(!f[i].isMember())
            return false;
    }

    Exponent x(uint64_t(0));
//    get_x(proof_.get_A(),proof_.get_C(), proof_.get_D(), x);
    x_ = x;
    for(int j = 0; j < m_; ++j){
        Exponent temp;
        for(int i = 1; i < n_; ++i){
            temp += f[j * n_ + i];
        }
        if(!(f[j * n_] == (x - temp)))
            return false;
    }

    GroupElement one;
    commit(g_, h_, f, proof_.get_ZA(), one);
    if(!((B_Commit * x + proof_.get_A()) == one))
        return false;

    std::vector<Exponent> f_;
    for(int i = 0; i < f.size(); i++)
        f_.push_back(f[i] * (x - f[i]));
    GroupElement two;
    commit(g_, h_, f_, proof_.get_ZC(), two);
    if(!((proof_.get_C() * x + proof_.get_D()) == two))
        return false;

    return true;
}

} //namespace sigma