#ifndef FIRO_LIBSPARK_BPPLUS_H
#define FIRO_LIBSPARK_BPPLUS_H

#include "bpplus_proof.h"
#include <secp256k1/include/MultiExponent.h>

namespace spark {
    
std::size_t log2(std::size_t n);
bool is_nonzero_power_of_2(std::size_t n);

class BPPlus {
public:
    BPPlus(
        const GroupElement& G,
        const GroupElement& H,
        const std::vector<GroupElement>& Gi,
        const std::vector<GroupElement>& Hi,
        const std::size_t N);
    
    void prove(const std::vector<Scalar>& unpadded_v, const std::vector<Scalar>& unpadded_r, const std::vector<GroupElement>& unpadded_C, BPPlusProof& proof);
    bool verify(const std::vector<GroupElement>& unpadded_C, const BPPlusProof& proof); // single proof
    bool verify(const std::vector<std::vector<GroupElement>>& unpadded_C, const std::vector<BPPlusProof>& proofs); // batch of proofs

private:
    GroupElement G;
    GroupElement H;
    std::vector<GroupElement> Gi;
    std::vector<GroupElement> Hi;
    std::size_t N;
    Scalar TWO_N_MINUS_ONE;
};

}

#endif
