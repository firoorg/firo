#include "challenge_generator.h"

namespace lelantus {

ChallengeGenerator::ChallengeGenerator() {
    data.resize(GroupElement::serialize_size);
    scalar_data.resize(32);
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

void ChallengeGenerator::add(const Scalar& scalar) {
    scalar.serialize(scalar_data.data());
    hash.Write(scalar_data.data(), scalar_data.size());
}

void ChallengeGenerator::add(const std::vector<Scalar>& scalars) {
    for (size_t i = 0; i < scalars.size(); ++i) {
        add(scalars[i]);
    }
}

void ChallengeGenerator::get_challenge(Scalar& result_out) {
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    do {
        hash.Finalize(result_data);
        result_out = result_data;
        add(result_out);
    } while (result_out.isZero() || !result_out.isMember());
}
}// namespace lelantus
