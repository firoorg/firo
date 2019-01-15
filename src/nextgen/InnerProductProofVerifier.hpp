namespace nextgen {

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
bool InnerProductProofVerifier<Exponent, GroupElement>::verify(const InnerProductProof<Exponent, GroupElement>& proof) {
    auto itr_l = proof.L_.begin();
    auto itr_r = proof.R_.begin();
    Exponent x;
    NextGenPrimitives<Exponent, GroupElement>::get_x(P_, x);
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
    NextGenPrimitives<Exponent, GroupElement>::get_x(*itr_l, *itr_r, x);
    //Compute g prime and p prime
    zcoin_common::GeneratorVector<Exponent, GroupElement> g_p = NextGenPrimitives<Exponent, GroupElement>::g_prime(g_, x);
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_p = NextGenPrimitives<Exponent, GroupElement>::h_prime(h_, x);
    //Compute P prime
    GroupElement p_p = NextGenPrimitives<Exponent, GroupElement>::p_prime(P_, *itr_l, *itr_r, x);
    return InnerProductProofVerifier(g_p, h_p, u_, p_p).verify_util(proof, ++itr_l, ++itr_r);
}

}// namespace nextgen