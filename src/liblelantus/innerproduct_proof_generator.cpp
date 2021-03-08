#include "innerproduct_proof_generator.h"
#include "../libzerocoin/Zerocoin.h"

namespace lelantus {
    
InnerProductProofGenerator::InnerProductProofGenerator(
        const std::vector<GroupElement>& g,
        const std::vector<GroupElement>& h,
        const GroupElement& u,
        bool afterFixes)
        : g_(g)
        , h_(h)
        , u_(u)
        , afterFixes_(afterFixes)
{
}

InnerProductProofGenerator::InnerProductProofGenerator(
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

void InnerProductProofGenerator::generate_proof(
        const std::vector<Scalar>& a,
        const std::vector<Scalar>& b,
        const Scalar& x,
        ChallengeGenerator* challengeGenerator,
        InnerProductProof& proof_out) {
    const Scalar c = LelantusPrimitives::scalar_dot_product(a.begin(), a.end(), b.begin(), b.end());
    compute_P(a, b, P_initial);
    u_ *= x;
    proof_out.c_ = c;
    P_ = (P_initial + u_ * c);
    generate_proof_util(a, b, challengeGenerator, proof_out);
}

void InnerProductProofGenerator::generate_proof_util(
        const std::vector<Scalar>& a,
        const std::vector<Scalar>& b,
        ChallengeGenerator* challengeGenerator,
        InnerProductProof& proof_out) {

    if(a.size() != b.size())
        throw ZerocoinException("Sizes of a and b are not equal.");

    if(a.size() == 1 && b.size() == 1) { //Protocol 2 line 15
        proof_out.a_ = a[0];
        proof_out.b_ = b[0];
        return;
    }

    std::size_t n = a.size() / 2;
    // Computes cL then L
    Scalar cL = LelantusPrimitives::scalar_dot_product(a.begin() ,a.begin() + n, b.begin() + n,  b.end());
    GroupElement L;
    l(a.begin() ,a.begin() + n, b.begin() + n,  b.end(), cL, L);

    //Computes cR then R
    Scalar cR = LelantusPrimitives::scalar_dot_product(a.begin() + n, a.end(), b.begin(), b.begin() + n);
    GroupElement R;
    r(a.begin() + n, a.end(), b.begin(), b.begin() + n, cR, R);

    //Push L and R
    proof_out.L_.emplace_back(L);
    proof_out.R_.emplace_back(R);

    //Get challenge x
    Scalar x;
    std::vector<GroupElement> group_elements = {L, R};

    if (afterFixes_) {
        std::string domain_separator = "INNER_PRODUCT";
        std::vector<unsigned char> pre(domain_separator.begin(), domain_separator.end());
        challengeGenerator->add(pre);
    } else {
        delete (challengeGenerator);
        challengeGenerator = new ChallengeGeneratorSha256();
    }
    challengeGenerator->add(group_elements);
    challengeGenerator->get_challenge(x);

    //Compute g prime and p prime
    std::vector<GroupElement> g_p;
    LelantusPrimitives::g_prime(g_, x, g_p);
    std::vector<GroupElement> h_p;
    LelantusPrimitives::h_prime(h_, x, h_p);

    //Compute a prime and b prime
    std::vector<Scalar> a_p = a_prime(x, a);
    std::vector<Scalar> b_p = b_prime(x, b);

    //Compute P prime
    GroupElement p_p = LelantusPrimitives::p_prime(P_, L, R, x);

    // Recursive call of protocol 2
    InnerProductProofGenerator(g_p, h_p, u_, p_p).generate_proof_util(a_p, b_p, challengeGenerator, proof_out);
}

void InnerProductProofGenerator::compute_P(
        const std::vector<Scalar>& a,
        const std::vector<Scalar>& b,
        GroupElement& result_out) {

    secp_primitives::MultiExponent g_mult(g_, a);
    secp_primitives::MultiExponent h_mult(h_, b);
    GroupElement g = g_mult.get_multiple();
    GroupElement h = h_mult.get_multiple();
    result_out = (g + h);
}

void InnerProductProofGenerator::l(
        typename std::vector<Scalar>::const_iterator a_start,
        typename std::vector<Scalar>::const_iterator a_end,
        typename std::vector<Scalar>::const_iterator b_start,
        typename std::vector<Scalar>::const_iterator b_end,
        const Scalar& cL,
        GroupElement& result_out) {
    std::vector<Scalar> a, b;
    std::vector<GroupElement> gens_g, gens_h;
    gens_g.reserve(g_.size() / 2 + 1);
    gens_h.reserve(h_.size() / 2 + 1);
    a.reserve(g_.size() / 2 + 1);
    b.reserve(h_.size() / 2 + 1);

    gens_g.insert(gens_g.end(), g_.begin() + g_.size() / 2, g_.end());
    a.insert(a.end(), a_start, a_start + g_.size() / 2);

    gens_h.insert(gens_h.end(), h_.begin(), h_.begin() + h_.size() / 2);
    b.insert(b.end(), b_start, b_start + h_.size() / 2);

    LelantusPrimitives::commit(u_, cL, gens_g, a, gens_h, b, result_out);
}

void InnerProductProofGenerator::r(
        typename std::vector<Scalar>::const_iterator a_start,
        typename std::vector<Scalar>::const_iterator a_end,
        typename std::vector<Scalar>::const_iterator b_start,
        typename std::vector<Scalar>::const_iterator b_end,
        const Scalar& cR,
        GroupElement& result_out) {
    std::vector<Scalar> a, b;
    std::vector<GroupElement> gens_g, gens_h;
    gens_g.reserve(g_.size() / 2 + 1);
    gens_h.reserve(h_.size() / 2 + 1);
    a.reserve(g_.size() / 2 + 1);
    b.reserve(h_.size() / 2 + 1);

    gens_g.insert(gens_g.end(), g_.begin(), g_.begin() + g_.size() / 2);
    a.insert(a.end(), a_start, a_start + g_.size() / 2);

    gens_h.insert(gens_h.end(), h_.begin() + h_.size() / 2, h_.end());
    b.insert(b.end(), b_start, b_start + h_.size() / 2);

    LelantusPrimitives::commit(u_, cR, gens_g, a, gens_h, b, result_out);
}

std::vector<Scalar> InnerProductProofGenerator::a_prime(
        const Scalar& x,
        const std::vector<Scalar>& a){
    Scalar x_inverse  = x.inverse();
    std::vector<Scalar> result;
    result.reserve(a.size() / 2);
    for(std::size_t i = 0; i < a.size() / 2; ++i)
    {
        result.emplace_back(a[i] * x + a[a.size() / 2 + i] * x_inverse);
    }
    return result;
}

std::vector<Scalar> InnerProductProofGenerator::b_prime(
        const Scalar& x,
        const std::vector<Scalar>& b) {
    Scalar x_inverse  = x.inverse();
    std::vector<Scalar> result;
    result.reserve(b.size() / 2);
    for(std::size_t i = 0; i < b.size() / 2; ++i)
    {
        result.emplace_back(b[i] * x_inverse + b[b.size() / 2 + i] * x);
    }
    return result;
}

const GroupElement& InnerProductProofGenerator::get_P() {
    return P_initial;
}
} // namespace lelantus
