#ifndef ZCOIN_LELANTUS_CHALLANGE_GENERATOR_H
#define ZCOIN_LELANTUS_CHALLANGE_GENERATOR_H

#include "../../crypto/sha256.h"

namespace lelantus {

template<class Exponent, class GroupElement>
class ChallengeGenerator {

public:
    void add(const GroupElement& group_element);
    void add(const std::vector<GroupElement>& group_elements);
    void get_challenge(Exponent& result_out);

private:
    CSHA256 hash;
};

}// namespace lelantus

#include "challange_generator.hpp"

#endif //ZCOIN_LELANTUS_CHALLANGE_GENERATOR_H
