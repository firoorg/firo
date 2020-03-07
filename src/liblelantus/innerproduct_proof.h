#ifndef ZCOIN_LIBLELANTUS_INNERPRODUCTPROOF_H
#define ZCOIN_LIBLELANTUS_INNERPRODUCTPROOF_H

#include <vector>
#include "params.h"

namespace lelantus {

// Storage of the proof.
template <class Exponent, class GroupElement>
class InnerProductProof {
public:

    inline int memoryRequired(int size) const {
        return a_.memoryRequired() * 3 + 34 * 2 * size;
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        buffer = a_.serialize(buffer);
        buffer = b_.serialize(buffer);
        buffer = c_.serialize(buffer);
        for (std::size_t i = 0; i < L_.size(); ++i)
            buffer = L_[i].serialize(buffer);
        for (std::size_t i = 0; i < R_.size(); ++i)
            buffer = R_[i].serialize(buffer);
        return buffer;
    }

    inline const unsigned char* deserialize(const unsigned char* buffer, int size) {
        buffer = a_.deserialize(buffer);
        buffer = b_.deserialize(buffer);
        buffer = c_.deserialize(buffer);
        L_.resize(size);
        for (int i = 0; i < size; ++i)
            buffer = L_[i].deserialize(buffer);
        R_.resize(size);
        for (int i = 0; i < size; ++i)
            buffer = R_[i].deserialize(buffer);
        return buffer;
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

#endif //ZCOIN_LIBLELANTUS_INNERPRODUCTPROOF_H
