namespace lelantus {

template<class Exponent, class GroupElement>
ChallengeGenerator<Exponent, GroupElement>::ChallengeGenerator() {
    data.resize(GroupElement::serialize_size);
}

template<class Exponent, class GroupElement>
void ChallengeGenerator<Exponent, GroupElement>::add(const GroupElement& group_element) {
    group_element.serialize(data.data());
    hash.Write(data.data(), data.size());
}

template<class Exponent, class GroupElement>
void ChallengeGenerator<Exponent, GroupElement>::add(const std::vector<GroupElement>& group_elements) {
    for (size_t i = 0; i < group_elements.size(); ++i) {
        add(group_elements[i]);
    }
}

template<class Exponent, class GroupElement>
void ChallengeGenerator<Exponent, GroupElement>::get_challenge(Exponent& result_out) {
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    hash.Finalize(result_data);
    result_out = result_data;
}
}// namespace lelantus
