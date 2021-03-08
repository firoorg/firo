#include "challenge_generator_sha256.h"

namespace lelantus {

ChallengeGeneratorSha256::ChallengeGeneratorSha256() {
    data.resize(GroupElement::serialize_size);
    scalar_data.resize(32);
}

void ChallengeGeneratorSha256::add(const GroupElement& group_element) {
    group_element.serialize(data.data());
    hash.Write(data.data(), data.size());
}


void ChallengeGeneratorSha256::add(const std::vector<GroupElement>& group_elements) {
    for (size_t i = 0; i < group_elements.size(); ++i) {
        add(group_elements[i]);
    }
}

void ChallengeGeneratorSha256::add(const Scalar& scalar) {
    scalar.serialize(scalar_data.data());
    hash.Write(scalar_data.data(), scalar_data.size());
}

void ChallengeGeneratorSha256::add(const std::vector<Scalar>& scalars) {
    for (size_t i = 0; i < scalars.size(); ++i) {
        add(scalars[i]);
    }
}

void ChallengeGeneratorSha256::add(const std::vector<unsigned char>& data_) {
    // do nothing, this function is for adding domain separator string, but we have no such strings before fixes, we use it another challenge generator after that
}

void ChallengeGeneratorSha256::get_challenge(Scalar& result_out) {
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    do {
        CSHA256 temp_hash = hash;
        hash.Finalize(result_data);
        hash = temp_hash;
        result_out = result_data;
        add(result_out);
    } while (result_out.isZero() || !result_out.isMember());
}
}// namespace lelantus
