#include "challenge_generator.h"

namespace lelantus {

template<class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::generate_challenge(
        const std::vector<GroupElement>& group_elements,
        Exponent& result_out) {
    if (group_elements.empty())
        throw std::runtime_error("Group elements empty while generating a challenge.");

    ChallengeGenerator<Exponent, GroupElement> challengeGenerator;
    challengeGenerator.add(group_elements);
    challengeGenerator.get_challenge(result_out);
}

template<class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::commit(const GroupElement& g,
                                                        const std::vector<GroupElement>& h,
                                                        const std::vector<Exponent>& exp,
                                                        const Exponent& r,
                                                        GroupElement& result_out) {
    secp_primitives::MultiExponent mult(h, exp);
    result_out = g * r + mult.get_multiple();
}

template<class Exponent, class GroupElement>
GroupElement LelantusPrimitives<Exponent, GroupElement>::commit(
        const GroupElement& g,
        const Exponent& m,
        const GroupElement& h,
        const Exponent& r) {
    return g * m + h * r;
}

template<class Exponent, class GroupElement>
GroupElement LelantusPrimitives<Exponent, GroupElement>::double_commit(
        const GroupElement& g,
        const Exponent& m,
        const GroupElement& hV,
        const Exponent& v,
        const GroupElement& hR,
        const Exponent& r) {
    return g * m + hV * v + hR * r;
}

template<class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::convert_to_sigma(
        uint64_t num,
        uint64_t n,
        uint64_t m,
        std::vector<Exponent>& out) {
    out.reserve(n * m);
    Exponent one(uint64_t(1));
    Exponent zero(uint64_t(0));

    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            if(i == (num % n))
                out.emplace_back(one);
            else
                out.emplace_back(zero);
        }
        num /= n;
    }
}

template<class Exponent, class GroupElement>
std::vector<uint64_t> LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(
        uint64_t num,
        uint64_t n,
        uint64_t m) {
    std::vector<uint64_t> result;
    result.reserve(m);
    while (num != 0)
    {
        result.emplace_back(num % n);
        num /= n;
    }
    result.resize(m);
    return result;
}

template<class Exponent, class GroupElement>
void  LelantusPrimitives<Exponent, GroupElement>::generate_Lelantus_challange(
        const std::vector<SigmaPlusProof<Exponent, GroupElement>>& proofs,
        Exponent& result_out) {
    if (proofs.size() > 0) {
        ChallengeGenerator<Exponent, GroupElement> challengeGenerator;
        for (std::size_t i = 0; i < proofs.size(); ++i) {
            challengeGenerator.add(proofs[i].A_);
            challengeGenerator.add(proofs[i].B_);
            challengeGenerator.add(proofs[i].C_);
            challengeGenerator.add(proofs[i].D_);
            challengeGenerator.add(proofs[i].Gk_);
            challengeGenerator.add(proofs[i].Qk);
        }

        challengeGenerator.get_challenge(result_out);
    }
    else
        result_out = uint64_t(1);
}

template<class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::new_factor(
        const Exponent& x,
        const Exponent& a,
        std::vector<Exponent>& coefficients) {
    if(coefficients.empty())
        throw ZerocoinException("Coefficients if empty.");

    std::size_t degree = coefficients.size();
    coefficients.push_back(x * coefficients[degree-1]);
    for (std::size_t d = degree-1; d >= 1; --d)
        coefficients[d] = a * coefficients[d] + x * coefficients[d-1];
    coefficients[0] *= a;
}

template<class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::commit(
        const GroupElement& h,
        const Exponent& h_exp,
        const std::vector<GroupElement>& g_,
        const std::vector<Exponent>& L,
        const std::vector<GroupElement>& h_,
        const std::vector<Exponent>& R,
        GroupElement& result_out) {
    secp_primitives::MultiExponent g_mult(g_, L);
    secp_primitives::MultiExponent h_mult(h_, R);
    result_out += h * h_exp + g_mult.get_multiple() + h_mult.get_multiple();
}

template <class Exponent, class GroupElement>
Exponent LelantusPrimitives<Exponent, GroupElement>::scalar_dot_product(
        typename std::vector<Exponent>::const_iterator a_start,
        typename std::vector<Exponent>::const_iterator a_end,
        typename std::vector<Exponent>::const_iterator b_start,
        typename std::vector<Exponent>::const_iterator b_end) {
    Exponent result(uint64_t(0));
    auto itr_a = a_start;
    auto itr_b = b_start;
    while (itr_a != a_end || itr_b != b_end)
    {
        result += ((*itr_a) * (*itr_b));
        ++itr_a;
        ++itr_b;
    }
    return result;
}


template <class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::g_prime(
        const std::vector<GroupElement>& g_,
        const Exponent& x,
        std::vector<GroupElement>& result){
    Exponent x_inverse = x.inverse();
    result.reserve(g_.size() / 2);
    for (std::size_t i = 0; i < g_.size() / 2; ++i)
    {
        result.push_back(((g_[i] * x_inverse) + (g_[g_.size() / 2 + i] * x)));
    }
}

template <class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::h_prime(
        const std::vector<GroupElement>& h_,
        const Exponent& x,
        std::vector<GroupElement>& result) {
    Exponent x_inverse = x.inverse();
    result.reserve(h_.size() / 2);
    for (std::size_t i = 0; i < h_.size() / 2; ++i)
    {
        result.push_back(((h_[i] * x) + (h_[h_.size() / 2 + i] * x_inverse)));
    }
}

template <class Exponent, class GroupElement>
GroupElement LelantusPrimitives<Exponent, GroupElement>::p_prime(
        const GroupElement& P_,
        const GroupElement& L,
        const GroupElement& R,
        const Exponent& x){
    Exponent x_square = x.square();
    return L * x_square + P_ + R * (x_square.inverse());
}

template <class Exponent, class GroupElement>
Exponent LelantusPrimitives<Exponent, GroupElement>::delta(const Exponent& y, const Exponent& z, uint64_t n,  uint64_t m){
    Exponent y_;
    Exponent two_;
    Exponent two(uint64_t(2));
    Exponent y_n(uint64_t(1));
    Exponent two_n(uint64_t(1));
    Exponent z_j =  z.exponent(uint64_t(3));
    Exponent z_sum(uint64_t(0));

    for(std::size_t j = 0; j < m; ++j)
    {
        for(std::size_t i = 0; i < n; ++i)
        {
            y_ += y_n;
            y_n *= y;
        }
        z_sum += z_j;
        z_j *= z;
    }

    for(std::size_t i = 0; i < n; ++i)
    {
        two_ += two_n;
        two_n *= two;
    }

    return (z - z.square()) * y_ - z_sum * two_;
}

}//namespace lelantus