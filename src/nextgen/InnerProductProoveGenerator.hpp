namespace nextgen {

template <class Exponent, class GroupElement>
InnerProductProoveGenerator<Exponent, GroupElement>::InnerProductProoveGenerator(
        const zcoin_common::GeneratorVector<Exponent, GroupElement>& g,
        const zcoin_common::GeneratorVector<Exponent, GroupElement>& h,
        const GroupElement& u)
        : g_(g)
        , h_(h)
        , u_(u)
{
}

template <class Exponent, class GroupElement>
InnerProductProoveGenerator<Exponent, GroupElement>::InnerProductProoveGenerator(
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
void InnerProductProoveGenerator<Exponent, GroupElement>::generate_proof(
        const std::vector<Exponent>& a,
        const std::vector<Exponent>& b,
        InnerProductProof<Exponent, GroupElement>& proof_out) {
    int n = a.size() / 2;
    const Exponent c = NextGenPrimitives<Exponent, GroupElement>::scalar_dot_product(a.begin(), a.end(), b.begin(), b.end());
    compute_P(a.begin(), a.end(), b.begin(), b.end(), P_initial);
    Exponent x;
    NextGenPrimitives<Exponent, GroupElement>::get_x(P_initial, x);
    u_ *= x;
    proof_out.c_ = c;
    P_ = (P_initial + u_ * c);
    generate_proof_util(a, b, proof_out);
}

template <class Exponent, class GroupElement>
void InnerProductProoveGenerator<Exponent, GroupElement>::generate_proof_util(
        const std::vector<Exponent>& a,
        const std::vector<Exponent>& b,
        InnerProductProof<Exponent, GroupElement>& proof_out) {

    if(a.size() == 1 && b.size() == 1){ //Protocol 2 line 15
        proof_out.a_ = a[0];
        proof_out.b_ = b[0];
        return;
    }

    int n = a.size() / 2;
    // Computes cL then L
    Exponent cL = NextGenPrimitives<Exponent, GroupElement>::scalar_dot_product(a.begin() ,a.begin() + n, b.begin() + n,  b.end());
    GroupElement L;
    l(a.begin() ,a.begin() + n, b.begin() + n,  b.end(), cL, L);
//    //Computes cR then R
    Exponent cR = NextGenPrimitives<Exponent, GroupElement>::scalar_dot_product(a.begin() + n, a.end(), b.begin(), b.begin() + n);
    GroupElement R;
    r(a.begin() + n, a.end(), b.begin(), b.begin() + n, cR, R);
//    //Push L and R
    proof_out.L_.push_back(L);
    proof_out.R_.push_back(R);
//    //Get challenge x
    Exponent x;
    NextGenPrimitives<Exponent, GroupElement>::get_x(L, R, x);
//    //Compute g prime and p prime
    zcoin_common::GeneratorVector<Exponent, GroupElement> g_p = NextGenPrimitives<Exponent, GroupElement>::g_prime(g_, x);
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_p = NextGenPrimitives<Exponent, GroupElement>::h_prime(h_, x);
//    //Compute a prime and b prime
    std::vector<Exponent> a_p = a_prime(x, a);
    std::vector<Exponent> b_p = b_prime(x, b);
//    //Compute P prime
    GroupElement p_p = NextGenPrimitives<Exponent, GroupElement>::p_prime(P_, L, R, x);
    // Recursive call of protocol 2
    InnerProductProoveGenerator(g_p, h_p, u_, p_p).generate_proof_util(a_p, b_p, proof_out);
}

//template <class Exponent, class GroupElement>
//void InnerProductProoveGenerator<Exponent, GroupElement>::hash(
//        typename std::vector<Exponent>::const_iterator a1_start,
//        typename std::vector<Exponent>::const_iterator a1_end,
//        typename std::vector<Exponent>::const_iterator a2_start,
//        typename std::vector<Exponent>::const_iterator a2_end,
//        typename std::vector<Exponent>::const_iterator b1_start,
//        typename std::vector<Exponent>::const_iterator b1_end,
//        typename std::vector<Exponent>::const_iterator b2_start,
//        typename std::vector<Exponent>::const_iterator b2_end,
//        const Exponent& c,
//        GroupElement& result_out) {
//    GroupElement g1, g2, h1, h2, uc;
//
//    g_.get_vector_multiple(0, g_.size()/2, a1_start, a1_end, g1);
//    g_.get_vector_multiple(g_.size() / 2, g_.size(), a2_start, a2_end, g2);
//
//    h_.get_vector_multiple(0, h_.size() / 2, b1_start, b1_end, h1);
//    h_.get_vector_multiple(h_.size() / 2, h_.size(), b2_start, b2_end, h2);
//
//    uc = u_ * c;
//
//    result_out = g1 + g2 + h1 + h2 + uc;
//}

template <class Exponent, class GroupElement>
void InnerProductProoveGenerator<Exponent, GroupElement>::compute_P(
        typename std::vector<Exponent>::const_iterator a_start,
        typename std::vector<Exponent>::const_iterator a_end,
        typename std::vector<Exponent>::const_iterator b_start,
        typename std::vector<Exponent>::const_iterator b_end,
        GroupElement& result_out) {
    GroupElement g, h;

    g_.get_vector_multiple(0, g_.size(), a_start, a_end, g);
    h_.get_vector_multiple(0, h_.size(), b_start, b_end, h);

    result_out = (g + h);
}

template <class Exponent, class GroupElement>
void InnerProductProoveGenerator<Exponent, GroupElement>::l(
        typename std::vector<Exponent>::const_iterator a_start,
        typename std::vector<Exponent>::const_iterator a_end,
        typename std::vector<Exponent>::const_iterator b_start,
        typename std::vector<Exponent>::const_iterator b_end,
        const Exponent& cL,
        GroupElement& result_out) {
    GroupElement g, h, ucL;

    g_.get_vector_multiple(g_.size() / 2 , g_.size(), a_start, a_end, g);
    h_.get_vector_multiple(0, h_.size() / 2, b_start, b_end, h);
    result_out = g + h + u_ * cL;
}

template <class Exponent, class GroupElement>
void InnerProductProoveGenerator<Exponent, GroupElement>::r(
        typename std::vector<Exponent>::const_iterator a_start,
        typename std::vector<Exponent>::const_iterator a_end,
        typename std::vector<Exponent>::const_iterator b_start,
        typename std::vector<Exponent>::const_iterator b_end,
        const Exponent& cR,
        GroupElement& result_out) {
    GroupElement g, h, ucR;

    g_.get_vector_multiple(0, g_.size() / 2, a_start, a_end, g);
    h_.get_vector_multiple(h_.size() / 2, h_.size(), b_start, b_end, h);
    result_out = g + h + u_ * cR;
}


template <class Exponent, class GroupElement>
std::vector<Exponent> InnerProductProoveGenerator<Exponent, GroupElement>::a_prime(
        const Exponent& x,
        const std::vector<Exponent>& a){
    Exponent x_inverse  = x.inverse();
    std::vector<Exponent> result;
    result.reserve(a.size() / 2);
    for(int i = 0; i < a.size() / 2; ++i){
        result.push_back(a[i] * x + a[a.size() / 2 + i] * x_inverse);
    }
    return  result;
}

template <class Exponent, class GroupElement>
std::vector<Exponent> InnerProductProoveGenerator<Exponent, GroupElement>::b_prime(
        const Exponent& x,
        const std::vector<Exponent>& b){
    Exponent x_inverse  = x.inverse();
    std::vector<Exponent> result;
    result.reserve(b.size() / 2);
    for(int i = 0; i < b.size() / 2; ++i){
        result.push_back(b[i] * x_inverse + b[b.size() / 2 + i] * x);
    }
    return  result;
}

template <class Exponent, class GroupElement>
GroupElement InnerProductProoveGenerator<Exponent, GroupElement>::get_P(){
    return P_initial;
}
} // namespace nextgen
