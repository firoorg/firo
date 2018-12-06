#ifndef ZCOIN_NEXTGENPROOF_H
#define ZCOIN_NEXTGENPROOF_H

#include "SchnorrProof.h"
#include "Params.h"

using namespace secp_primitives;

namespace nextgen{

class NextGenProof {
public:
    //n is the number of input coins
    inline int memoryRequired(int n) {
        sigma_proofs[0].memoryRequired() * n
        + schnorrProof.memoryRequired();
    }
    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = buffer;
        for(int i = 0; i < sigma_proofs.size(); ++i)
            current = sigma_proofs[i].serialize(current);
        return schnorrProof.serialize(current);
    }
    inline unsigned char* deserialize(const Params* params, unsigned char* buffer, int size) {
        unsigned char* current = buffer;
        for(int i = 0; i < size; ++i)
            current = sigma_proofs[i].deserialize(current, params->get_n(), params->get_m());
        return schnorrProof.deserialize(current);
    }

    std::vector<SigmaPlusProof<Scalar, GroupElement>> sigma_proofs;
    SchnorrProof<Scalar, GroupElement> schnorrProof;
};
}//namespace nextgen

#endif //ZCOIN_NEXTGENPROOF_H
