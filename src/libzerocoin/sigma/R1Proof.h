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

    inline int memoryRequired() const {
        return A_.memoryRequired() * 3 + ZA_.memoryRequired() * (f_.size() + 2);
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = A_.serialize(buffer);
        current = C_.serialize(current);
        current = D_.serialize(current);
        for(int i = 0; i < f_.size(); ++i)
            current = f_[i].serialize(current);
        current = ZA_.serialize(current);
        return ZC_.serialize(current);
    }
    inline unsigned char* deserialize(unsigned char* buffer, int f_size) {
        unsigned char* current = A_.deserialize(buffer);
        current = C_.deserialize(current);
        current = D_.deserialize(current);
        f_.resize(f_size);
        for(int i = 0; i < f_size; ++i)
            current = f_[i].deserialize(current);
        current = ZA_.deserialize(current);
        return ZC_.deserialize(current);
    }

    GroupElement A_;
    GroupElement C_;
    GroupElement D_;
    std::vector<Exponent> f_;
    Exponent ZA_;
    Exponent ZC_;
};

}// namespace sigma
#endif //ZCOIN_R1PROOF_H
