namespace zcoin_common {

template<class EXPONENT, class GROUP_ELEMENT>
GeneratorVector<EXPONENT, GROUP_ELEMENT>::GeneratorVector(
        const std::vector<GROUP_ELEMENT>& generators,
        std::size_t precomp)
        : precomp_(precomp) {

    powers_bits.resize(BIT_LENGTH);
    for (int j = 0; j < BIT_LENGTH; ++j) {
        powers_bits[j].resize(generators.size());
    }

    for (std::size_t i = 0; i < generators.size(); ++i) {
        generators_.push_back(generators[i]);
    }
    precomp_table_.resize(generators.size() / precomp + 1);
    GROUP_ELEMENT zero;
    std::size_t i;
    for (i = 0; i < generators.size() / precomp; i++) {
        precomp_table_[i].reserve(1 << precomp);
        rec_precompute(i, precomp, 0, zero);
    }
    if (generators.size() % precomp) {
        precomp_table_[i].reserve(1 << (generators.size() % precomp));
        rec_precompute(i, generators.size() % precomp, 0, zero);
    }

}

template<class EXPONENT, class GROUP_ELEMENT>
void GeneratorVector<EXPONENT, GROUP_ELEMENT>::rec_precompute(
        std::size_t i, std::size_t precomp, std::size_t current_id,
        const GROUP_ELEMENT& current) {
    if (current_id == precomp) {
        // save the result.

        precomp_table_[i].push_back(current);
        return;
    }
    rec_precompute(i, precomp, current_id + 1, current);
    GROUP_ELEMENT next = current;
    next += generators_[i * precomp_ + current_id];
    rec_precompute(i, precomp, current_id + 1, next);
}

template<class EXPONENT, class GROUP_ELEMENT>
const GROUP_ELEMENT &GeneratorVector<EXPONENT, GROUP_ELEMENT>::get_g(int i) const {
    return generators_[i];
}

template<class EXPONENT, class GROUP_ELEMENT>
void GeneratorVector<EXPONENT, GROUP_ELEMENT>::get_vector_subset_sum(
        const std::vector<bool>& bits, GROUP_ELEMENT &result_out) const {
    std::size_t i;
    for (i = 0; i < bits.size() / precomp_; i++) {
        int index = 0;
        for (std::size_t j = 0; j < precomp_; ++j) {
            index <<= 1;
            index += bits[i * precomp_ + j];
        }
        if (index != 0)
            result_out += precomp_table_[i][index];
    }
    if(bits.size() % precomp_) {
        int index = 0;
        for (std::size_t j = 0; j < bits.size() % precomp_; ++j) {
            index <<= 1;
            index += bits[i * precomp_ + j];
        }
            result_out += precomp_table_[i][index];
    }
}

template<class EXPONENT, class GROUP_ELEMENT>
void GeneratorVector<EXPONENT, GROUP_ELEMENT>::get_vector_multiple(
        int range_start, int range_end,
        typename std::vector<EXPONENT>::const_iterator power_start,
        typename std::vector<EXPONENT>::const_iterator power_end,
        GROUP_ELEMENT &result_out) const {

    for (int i = range_start; i < range_end; i++, power_start++)
        result_out += (get_g(i)) * (*power_start);

//    GROUP_ELEMENT result;
//    std::vector<std::vector<bool>> powers_bits;
//    powers_bits.resize(BIT_LENGTH);
//    for (int i = range_start; i < range_end; ++i) {
//        std::vector<bool> bits;
//        (power_start + i)->get_bits(bits);
//        for (int j = 0; j < BIT_LENGTH; ++j) {
//            powers_bits[j].push_back(bits[j]);
//        }
//    }
//    for (int i = 0; i < BIT_LENGTH; i++) {
////        result = result.square();
//        result += result;
//        get_vector_subset_sum(powers_bits[i], result);
//    }
//    result_out += result;
}

template<class EXPONENT, class GROUP_ELEMENT>
void GeneratorVector<EXPONENT, GROUP_ELEMENT>::get_vector_multiple(
        const std::vector<EXPONENT>& powers,
        GROUP_ELEMENT &result_out) const {
    GROUP_ELEMENT result;
    for (std::size_t i = 0; i < powers.size(); ++i) {
        std::vector<bool> bits;
        powers[i].get_bits(bits);
        for (int j = 0; j < BIT_LENGTH; ++j) {
            powers_bits[j][i] = bits[j];
        }
    }
//    for (int j = 0; j < BIT_LENGTH; ++j) {
//        for (int i = 0; i < powers.size(); ++i) {
//            std::cout << powers_bits[j][i] << ' ';
//        }
//        std::cout << std::endl;
//    }
    for (int i = 0; i < BIT_LENGTH; i++) {
        result.square();
        get_vector_subset_sum(powers_bits[i], result);
    }
    result_out += result;
}

template<class EXPONENT, class GROUP_ELEMENT>
int GeneratorVector<EXPONENT, GROUP_ELEMENT>::size() const {
    return generators_.size();
}

}//namespace zcoin_common
