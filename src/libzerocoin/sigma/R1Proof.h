#ifndef ZCOIN_R1PROOF_H
#define ZCOIN_R1PROOF_H

#include <vector>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>

namespace sigma {

template <class Exponent, class GroupElement>
class R1Proof{

public:
    R1Proof() = default;
    GroupElement A_;
    GroupElement C_;
    GroupElement D_;
    std::vector<Exponent> f_;
    Exponent ZA_;
    Exponent ZC_;
};

}// namespace sigma
#endif //ZCOIN_R1PROOF_H
