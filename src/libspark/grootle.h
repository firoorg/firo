#ifndef FIRO_LIBSPARK_GROOTLE_H
#define FIRO_LIBSPARK_GROOTLE_H

#include "grootle_proof.h"
#include <secp256k1/include/MultiExponent.h>
#include <random>
#include "util.h"

namespace spark {

class Grootle {

public:
    Grootle(
        const GroupElement& H,
        const std::vector<GroupElement>& Gi,
        const std::vector<GroupElement>& Hi,
        const std::size_t n,
        const std::size_t m
    );

    void prove(const std::size_t l,
        const Scalar& s,
        const std::vector<GroupElement>& S,
        const GroupElement& S1,
        const Scalar& v,
        const std::vector<GroupElement>& V,
        const GroupElement& V1,
        const std::vector<unsigned char>& root,
        GrootleProof& proof);
    bool verify(const std::vector<GroupElement>& S,
        const GroupElement& S1,
        const std::vector<GroupElement>& V,
        const GroupElement& V1,
        const std::vector<unsigned char>& root,
        const std::size_t size,
        const GrootleProof& proof); // single proof
    bool verify(const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& S1,
        const std::vector<GroupElement>& V,
        const std::vector<GroupElement>& V1,
        const std::vector<std::vector<unsigned char>>& roots,
        const std::vector<std::size_t>& sizes,
        const std::vector<GrootleProof>& proofs); // batch of proofs

private:
    GroupElement H;
    std::vector<GroupElement> Gi;
    std::vector<GroupElement> Hi;
    std::size_t n;
    std::size_t m;
};

}

#endif
