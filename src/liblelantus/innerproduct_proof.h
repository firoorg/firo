#ifndef FIRO_LIBLELANTUS_INNERPRODUCTPROOF_H
#define FIRO_LIBLELANTUS_INNERPRODUCTPROOF_H

#include <vector>
#include "params.h"

namespace lelantus {

// Storage of the proof.
class InnerProductProof {
public:

    inline std::size_t memoryRequired(std::size_t size) const {
        return a_.memoryRequired() * 3 + 34 * 2 * size;
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(a_);
        READWRITE(b_);
        READWRITE(c_);
        READWRITE(L_);
        READWRITE(R_);
    }

    Scalar a_;
    Scalar b_;
    Scalar c_;
    std::vector<GroupElement> L_;
    std::vector<GroupElement> R_;
};

} // namespace lelantus

#endif //FIRO_LIBLELANTUS_INNERPRODUCTPROOF_H
