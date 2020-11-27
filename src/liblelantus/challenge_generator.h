#ifndef ZCOIN_LELANTUS_CHALLENGE_GENERATOR_H
#define ZCOIN_LELANTUS_CHALLENGE_GENERATOR_H

#include "../../crypto/sha256.h"
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>

namespace lelantus {

using namespace secp_primitives;

class ChallengeGenerator {

public:
    ChallengeGenerator();
    void add(const GroupElement& group_element);
    void add(const std::vector<GroupElement>& group_elements);
    void add(const Scalar& scalar);
    void add(const std::vector<Scalar>& scalars);
    void get_challenge(Scalar& result_out);

private:
    CSHA256 hash;
    std::vector<unsigned char> data;
    std::vector<unsigned char> scalar_data;
};

}// namespace lelantus

#endif //ZCOIN_LELANTUS_CHALLENGE_GENERATOR_H
