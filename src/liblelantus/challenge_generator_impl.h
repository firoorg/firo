#ifndef FIRO_LELANTUS_CHALLENGE_GENERATOR_IMPL_H
#define FIRO_LELANTUS_CHALLENGE_GENERATOR_IMPL_H

#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "../../crypto/sha256.h"
#include "challenge_generator.h"

namespace lelantus {

using namespace secp_primitives;

template <class Hasher>
class ChallengeGeneratorImpl : public ChallengeGenerator {

public:
    ChallengeGeneratorImpl();
    void add(const GroupElement& group_element);
    void add(const std::vector<GroupElement>& group_elements);
    void add(const Scalar& scalar);
    void add(const std::vector<Scalar>& scalars);
    void add(const std::vector<unsigned char>& data_);
    void get_challenge(Scalar& result_out);

private:
    Hasher hash;
    std::vector<unsigned char> data;
    std::vector<unsigned char> scalar_data;
};

}// namespace lelantus

#include "challenge_generator_impl.hpp"

#endif //FIRO_LELANTUS_CHALLENGE_GENERATOR_IMPL_H
