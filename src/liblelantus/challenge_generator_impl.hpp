namespace lelantus {

template <class Hasher>
ChallengeGeneratorImpl<Hasher>::ChallengeGeneratorImpl() {
    data.resize(GroupElement::serialize_size);
    scalar_data.resize(32);
}

template <class Hasher>
void ChallengeGeneratorImpl<Hasher>::add(const GroupElement& group_element) {
    group_element.serialize(data.data());
    hash.Write(data.data(), data.size());
}

template <class Hasher>
void ChallengeGeneratorImpl<Hasher>::add(const std::vector<GroupElement>& group_elements) {
    for (size_t i = 0; i < group_elements.size(); ++i) {
        add(group_elements[i]);
    }
}

template <class Hasher>
void ChallengeGeneratorImpl<Hasher>::add(const Scalar& scalar) {
    scalar.serialize(scalar_data.data());
    hash.Write(scalar_data.data(), scalar_data.size());
}

template <class Hasher>
void ChallengeGeneratorImpl<Hasher>::add(const std::vector<Scalar>& scalars) {
    for (size_t i = 0; i < scalars.size(); ++i) {
        add(scalars[i]);
    }
}

template <class Hasher>
void ChallengeGeneratorImpl<Hasher>::add(const std::vector<unsigned char>& data_) {
    hash.Write(data_.data(), data_.size());
}

template <class Hasher>
void ChallengeGeneratorImpl<Hasher>::get_challenge(Scalar& result_out) {
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    do {
        Hasher temp_hash = hash;
        hash.Finalize(result_data);
        hash = temp_hash;
        result_out = result_data;
        add(result_out);
    } while (result_out.isZero() || !result_out.isMember());
}
}// namespace lelantus
