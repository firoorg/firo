#include "../../crypto/sha256.h"

namespace lelantus {

template<class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::generate_challenge(
        const std::vector<GroupElement>& group_elements,
        Exponent& result_out) {
    if (group_elements.empty())
        throw std::runtime_error("Group elements empty while generating a challenge.");
    CSHA256 hash;
    std::vector<unsigned char> data(group_elements.size() * group_elements[0].memoryRequired());
    unsigned char* current = data.data();
    for (size_t i = 0; i < group_elements.size(); ++i) {
        current = group_elements[i].serialize(current);
    }
    hash.Write(data.data(), data.size());
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    hash.Finalize(result_data);
    result_out = result_data;
}

template<class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::commit(const GroupElement& g,
                                                        const std::vector<GroupElement>& h,
                                                        const std::vector<Exponent>& exp,
                                                        const Exponent& r,
                                                        GroupElement& result_out) {
    secp_primitives::MultiExponent mult(h, exp);
    result_out += g * r + mult.get_multiple();
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
    std::size_t rem = 0;
    std::size_t j = 0;

    for (j = 0; j < m; ++j)
    {
        rem = num % n;
        num /= n;
        for (std::size_t i = 0; i < n; ++i)
        {
            if(i == rem)
                out.push_back(Exponent(uint64_t(1)));
            else
                out.push_back(Exponent(uint64_t(0)));
        }
    }
}

template<class Exponent, class GroupElement>
std::vector<uint64_t> LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(
        uint64_t num,
        uint64_t n,
        uint64_t m) {
    std::vector<uint64_t> result;
    uint64_t rem = 0;
    while (num != 0)
    {
        rem = num % n;
        num /= n;
        result.push_back(rem);;
    }
    result.resize(m);
    return result;
}

template<class Exponent, class GroupElement>
void  LelantusPrimitives<Exponent, GroupElement>::generate_Lelantus_challange(
        const std::vector<SigmaPlusProof<Exponent, GroupElement>>& proofs,
        Exponent& result_out) {
    if (proofs.size() > 0) {
        std::vector<GroupElement> group_elements;
        for (std::size_t i = 0; i < proofs.size(); ++i) {
            group_elements.emplace_back(proofs[i].A_);
            group_elements.emplace_back(proofs[i].B_);
            group_elements.emplace_back(proofs[i].C_);
            group_elements.emplace_back(proofs[i].D_);
            group_elements.insert(group_elements.end(), proofs[i].Gk_.begin(), proofs[i].Gk_.end());
            group_elements.insert(group_elements.end(), proofs[i].Qk.begin(), proofs[i].Qk.end());
        }
        LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, result_out);
    }
    else
        result_out = uint64_t(1);
}

template<class Exponent, class GroupElement>
void LelantusPrimitives<Exponent, GroupElement>::new_factor(
        const Exponent& x,
        const Exponent& a,
        std::vector<Exponent>& coefficients) {
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
    Exponent two;
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
        two += two_n;
        two_n *= uint64_t(2);
    }

    return (z - z.square()) * y_ - z_sum * two;
}

}//namespace lelantus