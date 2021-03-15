#include "challenge_generator_hash256.h"
namespace lelantus {

ChallengeGeneratorHash256::ChallengeGeneratorHash256() {
    data.resize(GroupElement::serialize_size);
    scalar_data.resize(32);
}

void ChallengeGeneratorHash256::add(const GroupElement& group_element) {
    group_element.serialize(data.data());
    hash.Write(data.data(), data.size());
}


void ChallengeGeneratorHash256::add(const std::vector<GroupElement>& group_elements) {
    for (size_t i = 0; i < group_elements.size(); ++i) {
        add(group_elements[i]);
    }
}

void ChallengeGeneratorHash256::add(const Scalar& scalar) {
    scalar.serialize(scalar_data.data());
    hash.Write(scalar_data.data(), scalar_data.size());
}

void ChallengeGeneratorHash256::add(const std::vector<Scalar>& scalars) {
    for (size_t i = 0; i < scalars.size(); ++i) {
        add(scalars[i]);
    }
}

void ChallengeGeneratorHash256::add(const std::vector<unsigned char>& data_) {
    hash.Write(data_.data(), data_.size());
}

void ChallengeGeneratorHash256::get_challenge(Scalar& result_out) {
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    // copy hasher in each generation, don't use length extension
    CHash256 hash_ = hash;
    do {
        CHash256 temp_hash = hash_;
        hash_.Finalize(result_data);
        hash_ = temp_hash;
        result_out = result_data;
        hash_.Write(result_data, CSHA256::OUTPUT_SIZE);
    } while (result_out.isZero() || !result_out.isMember());

    // add newly generated challenge for next generation,
    add(result_out);
}
}// namespace lelantus