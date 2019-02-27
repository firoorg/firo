namespace lelantus {

template <class Exponent, class GroupElement>
InnerProductProofVerifier<Exponent, GroupElement>::InnerProductProofVerifier(
        const zcoin_common::GeneratorVector<Exponent, GroupElement>& g,
        const zcoin_common::GeneratorVector<Exponent, GroupElement>& h,
        const GroupElement& u,
        const GroupElement& P)
        : g_(g)
        , h_(h)
        , u_(u)
        , P_(P)
{
}

template <class Exponent, class GroupElement>
bool InnerProductProofVerifier<Exponent, GroupElement>::verify(const Exponent& x, const InnerProductProof<Exponent, GroupElement>& proof) {
    auto itr_l = proof.L_.begin();
    auto itr_r = proof.R_.begin();
    u_  *= x;
    P_ += u_ * proof.c_;
    return verify_util(proof, itr_l, itr_r);
}

template <class Exponent, class GroupElement>
bool InnerProductProofVerifier<Exponent, GroupElement>::verify_util(
                                           const InnerProductProof<Exponent, GroupElement>& proof,
                                           typename std::vector<GroupElement>::const_iterator itr_l,
                                           typename std::vector<GroupElement>::const_iterator itr_r) {
    if((itr_l) == proof.L_.end()){
        Exponent c = proof.a_ * proof.b_;
        GroupElement uc = u_ * c;
        GroupElement P = g_.get_g(0) * proof.a_ + h_.get_g(0) * proof.b_ + uc;
        return P_ == P;
    }

    //Get challenge x
    Exponent x;
    LelantusPrimitives<Exponent, GroupElement>::get_x(*itr_l, *itr_r, x);
    //Compute g prime and p prime
    zcoin_common::GeneratorVector<Exponent, GroupElement> g_p = LelantusPrimitives<Exponent, GroupElement>::g_prime(g_, x);
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_p = LelantusPrimitives<Exponent, GroupElement>::h_prime(h_, x);
    //Compute P prime
    GroupElement p_p = LelantusPrimitives<Exponent, GroupElement>::p_prime(P_, *itr_l, *itr_r, x);
    return InnerProductProofVerifier(g_p, h_p, u_, p_p).verify_util(proof, ++itr_l, ++itr_r);
}

template <class Exponent, class GroupElement>
bool InnerProductProofVerifier<Exponent, GroupElement>::verify_fast(uint64_t n, const Exponent& x, const InnerProductProof<Exponent, GroupElement>& proof) {
    auto itr_l = proof.L_.begin();
    auto itr_r = proof.R_.begin();
    u_  *= x;
    P_ += u_ * proof.c_;
    return verify_fast_util(n, proof);
};


template <class Exponent, class GroupElement>
bool InnerProductProofVerifier<Exponent, GroupElement>::verify_fast_util(
        uint64_t n,
        const InnerProductProof<Exponent, GroupElement>& proof){
    int log_n = proof.L_.size();
    std::vector<Exponent> x_j, x_j_inv;
    x_j.resize(log_n);
    for(int i = 0; i < log_n; ++i) {
        LelantusPrimitives<Exponent, GroupElement>::get_x(proof.L_[i], proof.R_[i], x_j[i]);
    }
    std::vector<Exponent> s, s_inv;
    s.resize(n);
    s_inv.resize(n);
    for(uint64_t i = 0; i < n; ++i){
        Exponent x_i(uint64_t(1));
        for(int j = 0; j < log_n; ++j) {
            if((i >> j) & 1) {
                x_i *= x_j[log_n - j - 1];
            } else{
                x_i *= x_j[log_n - j - 1].inverse();
            }

        }
        s[i] =  x_i;
        s_inv[i] = x_i.inverse();
    }

    GroupElement g;
    GroupElement h;
    g_.get_vector_multiple(s, g);
    h_.get_vector_multiple(s_inv, h);

    GroupElement left;
    left += g * proof.a_ +  h * proof.b_ + u_ * (proof.a_ * proof.b_);
    GroupElement right = P_;
    GroupElement multi;
    Exponent two(uint64_t(2));
    for(int j = 0; j < log_n; ++j)
        multi += (proof.L_[j] * (x_j[j].square()) + proof.R_[j] * (x_j[j].exponent(two).inverse()));
    right += multi;
    if(left != right)
        return false;
    return true;
}

}// namespace lelantus