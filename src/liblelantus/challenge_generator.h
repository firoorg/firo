#ifndef FIRO_LELANTUS_CHALLENGE_GENERATOR_H
#define FIRO_LELANTUS_CHALLENGE_GENERATOR_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
namespace lelantus {
using namespace secp_primitives;

class ChallengeGenerator {
public:
    virtual ~ChallengeGenerator() {};
    virtual void add(const GroupElement& group_element) = 0;
    virtual void add(const std::vector<GroupElement>& group_elements) = 0;
    virtual void add(const Scalar& scalar) = 0;
    virtual void add(const std::vector<Scalar>& scalars) = 0;
    virtual void add(const std::vector<unsigned char>& data_) = 0;
    virtual void get_challenge(Scalar& result_out) = 0;
};

}// namespace lelantus

#endif //FIRO_LELANTUS_CHALLENGE_GENERATOR_H
