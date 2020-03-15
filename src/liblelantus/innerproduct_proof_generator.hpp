#include "../libzerocoin/Zerocoin.h"

namespace lelantus {

template <class Exponent, class GroupElement>
InnerProductProoveGenerator<Exponent, GroupElement>::InnerProductProoveGenerator(
        const std::vector<GroupElement>& g,
        const std::vector<GroupElement>& h,
        const GroupElement& u)
        : g_(g)
        , h_(h)
        , u_(u)
{
}

template <class Exponent, class GroupElement>
InnerProductProoveGenerator<Exponent, GroupElement>::InnerProductProoveGenerator(
        const std::vector<GroupElement>& g,
        const std::vector<GroupElement>& h,
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
        const Exponent& x,
        InnerProductProof<Exponent, GroupElement>& proof_out) {
    const Exponent c = LelantusPrimitives<Exponent, GroupElement>::scalar_dot_product(a.begin(), a.end(), b.begin(), b.end());
    compute_P(a, b, P_initial);
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

    if(a.size() != b.size())
        throw ZerocoinException("Sizes of a and b are not equal.");

    if(a.size() == 1 && b.size() == 1) { //Protocol 2 line 15
        proof_out.a_ = a[0];
        proof_out.b_ = b[0];
        return;
    }

    std::size_t n = a.size() / 2;
    // Computes cL then L
    Exponent cL = LelantusPrimitives<Exponent, GroupElement>::scalar_dot_product(a.begin() ,a.begin() + n, b.begin() + n,  b.end());
    GroupElement L;
    l(a.begin() ,a.begin() + n, b.begin() + n,  b.end(), cL, L);

    //Computes cR then R
    Exponent cR = LelantusPrimitives<Exponent, GroupElement>::scalar_dot_product(a.begin() + n, a.end(), b.begin(), b.begin() + n);
    GroupElement R;
    r(a.begin() + n, a.end(), b.begin(), b.begin() + n, cR, R);

    //Push L and R
    proof_out.L_.emplace_back(L);
    proof_out.R_.emplace_back(R);

    //Get challenge x
    Exponent x;
    std::vector<GroupElement> group_elements = {L, R};
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x);

    //Compute g prime and p prime
    std::vector<GroupElement> g_p;
    LelantusPrimitives<Exponent, GroupElement>::g_prime(g_, x, g_p);
    std::vector<GroupElement> h_p;
    LelantusPrimitives<Exponent, GroupElement>::h_prime(h_, x, h_p);

    //Compute a prime and b prime
    std::vector<Exponent> a_p = a_prime(x, a);
    std::vector<Exponent> b_p = b_prime(x, b);

    //Compute P prime
    GroupElement p_p = LelantusPrimitives<Exponent, GroupElement>::p_prime(P_, L, R, x);

    // Recursive call of protocol 2
    InnerProductProoveGenerator(g_p, h_p, u_, p_p).generate_proof_util(a_p, b_p, proof_out);
}

template <class Exponent, class GroupElement>
void InnerProductProoveGenerator<Exponent, GroupElement>::compute_P(
        const std::vector<Exponent>& a,
        const std::vector<Exponent>& b,
        GroupElement& result_out) {

    secp_primitives::MultiExponent g_mult(g_, a);
    secp_primitives::MultiExponent h_mult(h_, b);
    GroupElement g = g_mult.get_multiple();
    GroupElement h = h_mult.get_multiple();
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
    std::vector<Exponent> a, b;
    std::vector<GroupElement> gens_g, gens_h;
    gens_g.reserve(g_.size() / 2 + 1);
    gens_h.reserve(h_.size() / 2 + 1);
    a.reserve(g_.size() / 2 + 1);
    b.reserve(h_.size() / 2 + 1);

    gens_g.insert(gens_g.end(), g_.begin() + g_.size() / 2, g_.end());
    a.insert(a.end(), a_start, a_start + g_.size() / 2);

    gens_h.insert(gens_h.end(), h_.begin(), h_.begin() + h_.size() / 2);
    b.insert(b.end(), b_start, b_start + h_.size() / 2);

    LelantusPrimitives<Exponent, GroupElement>::commit(u_, cL, gens_g, a, gens_h, b, result_out);
}

template <class Exponent, class GroupElement>
void InnerProductProoveGenerator<Exponent, GroupElement>::r(
        typename std::vector<Exponent>::const_iterator a_start,
        typename std::vector<Exponent>::const_iterator a_end,
        typename std::vector<Exponent>::const_iterator b_start,
        typename std::vector<Exponent>::const_iterator b_end,
        const Exponent& cR,
        GroupElement& result_out) {
    std::vector<Exponent> a, b;
    std::vector<GroupElement> gens_g, gens_h;
    gens_g.reserve(g_.size() / 2 + 1);
    gens_h.reserve(h_.size() / 2 + 1);
    a.reserve(g_.size() / 2 + 1);
    b.reserve(h_.size() / 2 + 1);

    gens_g.insert(gens_g.end(), g_.begin(), g_.begin() + g_.size() / 2);
    a.insert(a.end(), a_start, a_start + g_.size() / 2);

    gens_h.insert(gens_h.end(), h_.begin() + h_.size() / 2, h_.end());
    b.insert(b.end(), b_start, b_start + h_.size() / 2);

    LelantusPrimitives<Exponent, GroupElement>::commit(u_, cR, gens_g, a, gens_h, b, result_out);
}


template <class Exponent, class GroupElement>
std::vector<Exponent> InnerProductProoveGenerator<Exponent, GroupElement>::a_prime(
        const Exponent& x,
        const std::vector<Exponent>& a){
    Exponent x_inverse  = x.inverse();
    std::vector<Exponent> result;
    result.reserve(a.size() / 2);
    for(std::size_t i = 0; i < a.size() / 2; ++i)
    {
        result.emplace_back(a[i] * x + a[a.size() / 2 + i] * x_inverse);
    }
    return result;
}

template <class Exponent, class GroupElement>
std::vector<Exponent> InnerProductProoveGenerator<Exponent, GroupElement>::b_prime(
        const Exponent& x,
        const std::vector<Exponent>& b) {
    Exponent x_inverse  = x.inverse();
    std::vector<Exponent> result;
    result.reserve(b.size() / 2);
    for(std::size_t i = 0; i < b.size() / 2; ++i)
    {
        result.emplace_back(b[i] * x_inverse + b[b.size() / 2 + i] * x);
    }
    return result;
}

template <class Exponent, class GroupElement>
const GroupElement& InnerProductProoveGenerator<Exponent, GroupElement>::get_P() {
    return P_initial;
}
} // namespace lelantus
