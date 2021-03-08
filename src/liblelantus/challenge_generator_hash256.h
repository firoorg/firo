#ifndef FIRO_LELANTUS_CHALLENGE_GENERATOR_HASH256_H
#define FIRO_LELANTUS_CHALLENGE_GENERATOR_HASH256_H

#include "challenge_generator.h"
#include "../hash.h"
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>

namespace lelantus {

using namespace secp_primitives;

class ChallengeGeneratorHash256 : public ChallengeGenerator {

public:
    ChallengeGeneratorHash256();
    void add(const GroupElement& group_element);
    void add(const std::vector<GroupElement>& group_elements);
    void add(const Scalar& scalar);
    void add(const std::vector<Scalar>& scalars);
    void add(const std::vector<unsigned char>& data_);
    void get_challenge(Scalar& result_out);

private:
    CHash256 hash;
    std::vector<unsigned char> data;
    std::vector<unsigned char> scalar_data;
};

}// namespace lelantus


#endif //FIRO_LELANTUS_CHALLENGE_GENERATOR_HASH256_H
