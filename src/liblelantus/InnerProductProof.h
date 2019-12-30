#ifndef ZCOIN_INNERPRODUCTPROOF_H
#define ZCOIN_INNERPRODUCTPROOF_H

#include <vector>
#include "Params.h"

namespace lelantus {

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
        for (int i = 0; i < L_.size(); ++i)
            current = L_[i].serialize(current);
        for (int i = 0; i < R_.size(); ++i)
            current = R_[i].serialize(current);
        return current;
    }

    inline const unsigned char* deserialize(const unsigned char* buffer, int size) {
        const unsigned char* current = a_.deserialize(buffer);
        current = b_.deserialize(current);
        current = c_.deserialize(current);
        L_.resize(size);
        for (int i = 0; i < size; ++i)
            current = L_[i].deserialize(current);
        R_.resize(size);
        for (int i = 0; i < size; ++i)
            current = R_[i].deserialize(current);
        return current;
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(a_);
        READWRITE(b_);
        READWRITE(c_);
        READWRITE(L_);
        READWRITE(R_);
    }

    Exponent a_;
    Exponent b_;
    Exponent c_;
    std::vector<GroupElement> L_;
    std::vector<GroupElement> R_;
};

} // namespace lelantus

#endif //ZCOIN_INNERPRODUCTPROOF_H
