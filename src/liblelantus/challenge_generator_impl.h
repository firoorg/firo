#ifndef FIRO_LELANTUS_CHALLENGE_GENERATOR_IMPL_H
#define FIRO_LELANTUS_CHALLENGE_GENERATOR_IMPL_H

#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "../../crypto/sha256.h"
#include "challenge_generator.h"
#include <iostream>
namespace lelantus {

using namespace secp_primitives;

template <class Hasher>
class ChallengeGeneratorImpl : public ChallengeGenerator {

public:
    ChallengeGeneratorImpl(int version_ = 0) {
        version = version_;
        data.resize(GroupElement::serialize_size);
        scalar_data.resize(32);
    }

    void add(const GroupElement& group_element) {
        group_element.serialize(data.data());
        hash.Write(data.data(), data.size());
    }

    void add(const std::vector<GroupElement>& group_elements) {
        addSize(group_elements.size());
        for (size_t i = 0; i < group_elements.size(); ++i) {
            add(group_elements[i]);
        }
    }

    void add(const Scalar& scalar) {
        scalar.serialize(scalar_data.data());
        hash.Write(scalar_data.data(), scalar_data.size());
    }

    void add(const std::vector<Scalar>& scalars) {
        addSize(scalars.size());
        for (size_t i = 0; i < scalars.size(); ++i) {
            add(scalars[i]);
        }
    }

    void add(const std::vector<unsigned char>& data_) {
        hash.Write(data_.data(), data_.size());
    }

    void get_challenge(Scalar& result_out) {
        unsigned char result_data[CSHA256::OUTPUT_SIZE];
        do {
            Hasher temp_hash = hash;
            hash.Finalize(result_data);
            hash = temp_hash;
            result_out = result_data;
            add(result_out);
        } while (result_out.isZero() || !result_out.isMember());
    }

private:
    void addSize(uint32_t size) {
        if (version >= 1) {
            Scalar s(size);
            add(s);
        }
    }
private:
    int version;
    Hasher hash;
    std::vector<unsigned char> data;
    std::vector<unsigned char> scalar_data;
};

}// namespace lelantus

#endif //FIRO_LELANTUS_CHALLENGE_GENERATOR_IMPL_H
