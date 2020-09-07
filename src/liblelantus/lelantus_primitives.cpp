#include "lelantus_primitives.h"
#include "challenge_generator.h"

namespace lelantus {
    
void LelantusPrimitives::generate_challenge(
        const std::vector<GroupElement>& group_elements,
        Scalar& result_out) {
    if (group_elements.empty())
        throw std::runtime_error("Group elements empty while generating a challenge.");

    ChallengeGenerator challengeGenerator;
    challengeGenerator.add(group_elements);
    challengeGenerator.get_challenge(result_out);
}

void LelantusPrimitives::commit(const GroupElement& g,
                                                        const std::vector<GroupElement>& h,
                                                        const std::vector<Scalar>& exp,
                                                        const Scalar& r,
                                                        GroupElement& result_out) {
    secp_primitives::MultiExponent mult(h, exp);
    result_out = g * r + mult.get_multiple();
}

GroupElement LelantusPrimitives::commit(
        const GroupElement& g,
        const Scalar& m,
        const GroupElement& h,
        const Scalar& r) {
    return g * m + h * r;
}

GroupElement LelantusPrimitives::double_commit(
        const GroupElement& g,
        const Scalar& m,
        const GroupElement& hV,
        const Scalar& v,
        const GroupElement& hR,
        const Scalar& r) {
    return g * m + hV * v + hR * r;
}

void LelantusPrimitives::convert_to_sigma(
        uint64_t num,
        uint64_t n,
        uint64_t m,
        std::vector<Scalar>& out) {
    out.reserve(n * m);
    Scalar one(uint64_t(1));
    Scalar zero(uint64_t(0));

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

std::vector<uint64_t> LelantusPrimitives::convert_to_nal(
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

void  LelantusPrimitives::generate_Lelantus_challange(
        const std::vector<SigmaExtendedProof>& proofs,
        const std::vector<PublicCoin>& Cout,
        Scalar& result_out) {

    result_out = uint64_t(1);

    if(Cout.size() > 0) {
        for(auto coin : Cout)
            challengeGenerator.add(coin.getValue());
    }

    if (proofs.size() > 0) {
        ChallengeGenerator challengeGenerator;
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
}

void LelantusPrimitives::new_factor(
        const Scalar& x,
        const Scalar& a,
        std::vector<Scalar>& coefficients) {
    if(coefficients.empty())
        throw ZerocoinException("Coefficients if empty.");

    std::size_t degree = coefficients.size();
    coefficients.push_back(x * coefficients[degree-1]);
    for (std::size_t d = degree-1; d >= 1; --d)
        coefficients[d] = a * coefficients[d] + x * coefficients[d-1];
    coefficients[0] *= a;
}

void LelantusPrimitives::commit(
        const GroupElement& h,
        const Scalar& h_exp,
        const std::vector<GroupElement>& g_,
        const std::vector<Scalar>& L,
        const std::vector<GroupElement>& h_,
        const std::vector<Scalar>& R,
        GroupElement& result_out) {
    secp_primitives::MultiExponent g_mult(g_, L);
    secp_primitives::MultiExponent h_mult(h_, R);
    result_out += h * h_exp + g_mult.get_multiple() + h_mult.get_multiple();
}

Scalar LelantusPrimitives::scalar_dot_product(
        typename std::vector<Scalar>::const_iterator a_start,
        typename std::vector<Scalar>::const_iterator a_end,
        typename std::vector<Scalar>::const_iterator b_start,
        typename std::vector<Scalar>::const_iterator b_end) {
    Scalar result(uint64_t(0));
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

void LelantusPrimitives::g_prime(
        const std::vector<GroupElement>& g_,
        const Scalar& x,
        std::vector<GroupElement>& result){
    Scalar x_inverse = x.inverse();
    result.reserve(g_.size() / 2);
    for (std::size_t i = 0; i < g_.size() / 2; ++i)
    {
        result.push_back(((g_[i] * x_inverse) + (g_[g_.size() / 2 + i] * x)));
    }
}

void LelantusPrimitives::h_prime(
        const std::vector<GroupElement>& h_,
        const Scalar& x,
        std::vector<GroupElement>& result) {
    Scalar x_inverse = x.inverse();
    result.reserve(h_.size() / 2);
    for (std::size_t i = 0; i < h_.size() / 2; ++i)
    {
        result.push_back(((h_[i] * x) + (h_[h_.size() / 2 + i] * x_inverse)));
    }
}

GroupElement LelantusPrimitives::p_prime(
        const GroupElement& P_,
        const GroupElement& L,
        const GroupElement& R,
        const Scalar& x){
    Scalar x_square = x.square();
    return L * x_square + P_ + R * (x_square.inverse());
}

Scalar LelantusPrimitives::delta(const Scalar& y, const Scalar& z, uint64_t n,  uint64_t m){
    Scalar y_;
    Scalar two_;
    NthPower y_n(y);
    NthPower two_n(uint64_t(2));
    NthPower z_j(z, z.exponent(uint64_t(3)));
    Scalar z_sum(uint64_t(0));

    for(std::size_t j = 0; j < m; ++j)
    {
        for(std::size_t i = 0; i < n; ++i)
        {
            y_ += y_n.pow;
            y_n.go_next();
        }
        z_sum += z_j.pow;
        z_j.go_next();
    }

    for(std::size_t i = 0; i < n; ++i)
    {
        two_ += two_n.pow;
        two_n.go_next();
    }

    return (z - z.square()) * y_ - z_sum * two_;
}

}//namespace lelantus