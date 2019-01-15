#ifndef ZCOIN_INNERPRODUCTPROOF_H
#define ZCOIN_INNERPRODUCTPROOF_H

#include <vector>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>

namespace nextgen {

// Storage of the proof.
template <class Exponent, class GroupElement>
class InnerProductProof {
public:

    inline int memoryRequired(int size) {
        return a_.memoryRequired() * 3 + 34 * 2 * size;
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = a_.serialize(buffer);
        current = b_.serialize(current);
        current = c_.serialize(current);
        for(int i = 0; i < L_.size(); ++i)
            current = L_[i].serialize();
        for(int i = 0; i < R_.size(); ++i)
            current = R_[i].serialize();
        return current;
    }
    inline unsigned char* deserialize(unsigned char* buffer, int size) {
        unsigned char* current = a_.deserialize(buffer);
        current = b_.deserialize(current);
        current = c_.deserialize(current);
        L_.resize(size);
        for(int i = 0; i < size; ++i)
            current = L_[i].deserialize();
        R_.resize(size);
        for(int i = 0; i < size; ++i)
            current = R_[i].deserialize();
        return current;
    }

    Exponent a_;
    Exponent b_;
    Exponent c_;
    std::vector<GroupElement> L_;
    std::vector<GroupElement> R_;
};

} // namespace nextgen

#endif //ZCOIN_INNERPRODUCTPROOF_H
