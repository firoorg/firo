#include "challenge_generator.h"

namespace lelantus {

ChallengeGenerator::ChallengeGenerator() {
    data.resize(GroupElement::serialize_size);
}

void ChallengeGenerator::add(const GroupElement& group_element) {
    group_element.serialize(data.data());
    hash.Write(data.data(), data.size());
}

void ChallengeGenerator::add(const std::vector<GroupElement>& group_elements) {
    for (size_t i = 0; i < group_elements.size(); ++i) {
        add(group_elements[i]);
    }
}

void ChallengeGenerator::get_challenge(Scalar& result_out) {
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    hash.Finalize(result_data);
    result_out = result_data;
}
}// namespace lelantus
