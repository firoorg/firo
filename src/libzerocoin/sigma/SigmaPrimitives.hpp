namespace sigma{

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::commit(const GroupElement& g,
        const zcoin_common::GeneratorVector<Exponent, GroupElement>& h,
        const std::vector<Exponent>& exp,
        const Exponent& r,
        GroupElement& result_out)  {
    result_out += g * r;
    h.get_vector_multiple(exp, result_out);
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
    int rem, nalNumber = 0;
    int j = 0;

    while (num != 0)
    {
        rem = num % n;
        num /= n;
        for(int i = 0; i < n; ++i){
            if(i == rem)
                out.push_back(Exponent(uint64_t(1)));
            else
                out.push_back(Exponent(uint64_t(0)));
        }
        j++;
    }

    for(int k = j; k < m; ++k){
        out.push_back(Exponent(uint64_t(1)));
        for(int i = 1; i < n; ++i){
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
    uint64_t rem, nalNumber = 0;
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
        const GroupElement D,
        Exponent& result_out) {
    secp256k1_sha256_t hash;
    secp256k1_sha256_initialize(&hash);
    unsigned char data[6 * sizeof(secp256k1_fe)];
    unsigned char *A_serial = A.serialize();
    unsigned char *C_serial = C.serialize();
    unsigned char *D_serial = D.serialize();
    memcpy(&data[0], &A_serial[0], 2 * sizeof(secp256k1_fe));
    memcpy(&data[0] + 2 * sizeof(secp256k1_fe), &C_serial[0], 2 * sizeof(secp256k1_fe));
    memcpy(&data[0] + 4 * sizeof(secp256k1_fe), &D_serial[0], 2 * sizeof(secp256k1_fe));
    secp256k1_sha256_write(&hash, &data[0], 6 * sizeof(secp256k1_fe));
    unsigned char result_data[32];
    secp256k1_sha256_finalize(&hash, result_data);
    delete [] A_serial;
    delete [] C_serial;
    delete [] D_serial;
    result_out = result_data;
}



template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::new_factor(
        Exponent x,
        Exponent a,
        std::vector<Exponent>& coefficients) {
    std::vector<Exponent> temp;
    temp.resize(coefficients.size() + 1);
    for(int j = 0; j < coefficients.size(); j++)
        temp[j] += x * coefficients[j];
    for(int j = 0; j < coefficients.size(); j++)
        temp[j + 1] += a * coefficients[j];
    coefficients = temp;
}

}//namespace sigma