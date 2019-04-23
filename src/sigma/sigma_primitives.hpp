#include "../../crypto/sha256.h"

namespace sigma{

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::commit(const GroupElement& g,
        const std::vector<GroupElement>& h,
        const std::vector<Exponent>& exp,
        const Exponent& r,
        GroupElement& result_out)  {
    secp_primitives::MultiExponent mult(h, exp);
    result_out += g * r + mult.get_multiple();
}

template<class Exponent, class GroupElement>
GroupElement SigmaPrimitives<Exponent, GroupElement>::commit(
        const GroupElement& g,
        const Exponent m,
        const GroupElement h,
        const Exponent r){
    return g * m + h * r;
}

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::convert_to_sigma(
        uint64_t num,
        uint64_t n,
        uint64_t m,
        std::vector<Exponent>& out){
    uint64_t rem;
    uint64_t j = 0;

    while (num != 0)
    {
        rem = num % n;
        num /= n;
        for (uint64_t i = 0; i < n; ++i) {
            if(i == rem)
                out.push_back(Exponent(uint64_t(1)));
            else
                out.push_back(Exponent(uint64_t(0)));
        }
        j++;
    }

    for (uint64_t k = j; k < m; ++k) {
        out.push_back(Exponent(uint64_t(1)));
        for (uint64_t i = 1; i < n; ++i) {
            out.push_back(Exponent(uint64_t(0)));
        }
    }
}

template<class Exponent, class GroupElement>
std::vector<uint64_t> SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(
        uint64_t num,
        uint64_t n,
        uint64_t m){
    std::vector<uint64_t> result;
    uint64_t rem;
    uint64_t j = 0;
    while (num != 0)
    {
        rem = num % n;
        num /= n;
        result.push_back(rem);
        j++;
    }
    result.resize(m);
    return result;
}

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::get_x(
        const GroupElement& A,
        const GroupElement& C,
        const GroupElement& D,
        Exponent& result_out) {
    CSHA256 hash;
    unsigned char data[3 * A.serialize_size];
    unsigned char* current = A.serialize(data);
    current = C.serialize(current);
    D.serialize(current);
    hash.Write(data, 3 * A.memoryRequired());
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    hash.Finalize(result_data);
    result_out = result_data;
}

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::new_factor(
        Exponent x,
        Exponent a,
        std::vector<Exponent>& coefficients) {
    std::vector<Exponent> temp;
    temp.resize(coefficients.size() + 1);
    for (std::size_t j = 0; j < coefficients.size(); j++)
        temp[j] += x * coefficients[j];
    for(std::size_t j = 0; j < coefficients.size(); j++)
        temp[j + 1] += a * coefficients[j];
    coefficients = temp;
}

} // namespace sigma
