#ifndef FIRO_LIBSPARK_CLAIM_H
#define FIRO_LIBSPARK_CLAIM_H

#include "chaum_proof.h"
#include <secp256k1/include/MultiExponent.h>

namespace spark {

// A claim proof, which is used to assert control of the consumed coins in a spend transaction
class Claim {
public:
    Claim(const GroupElement& F, const GroupElement& G, const GroupElement& H, const GroupElement& U);

    void prove(
        const Scalar& mu,
        const std::vector<unsigned char>& identifier,
        const std::vector<unsigned char>& message,
        const std::vector<Scalar>& x,
        const std::vector<Scalar>& y,
        const std::vector<Scalar>& z,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        ChaumProof& proof
    );
    bool verify(
        const Scalar& mu,
        const std::vector<unsigned char>& identifier,
        const std::vector<unsigned char>& message,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        const ChaumProof& proof
    );

private:
    Scalar challenge(
        const Scalar& mu,
        const std::vector<unsigned char>& identifier,
        const std::vector<unsigned char>& message,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        const GroupElement& A1,
        const std::vector<GroupElement>& A2
    );
    const GroupElement& F;
    const GroupElement& G;
    const GroupElement& H;
    const GroupElement& U;
};

}

#endif
