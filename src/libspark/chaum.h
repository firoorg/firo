#ifndef FIRO_LIBSPARK_CHAUM_H
#define FIRO_LIBSPARK_CHAUM_H

#include "chaum_proof.h"
#include <secp256k1/include/MultiExponent.h>

namespace spark {

class Chaum {
public:
    Chaum(const GroupElement& F, const GroupElement& G, const GroupElement& H, const GroupElement& U);

    void prove(
        const Scalar& mu,
        const std::vector<Scalar>& x,
        const std::vector<Scalar>& y,
        const std::vector<Scalar>& z,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        ChaumProof& proof
    );
    bool verify(
        const Scalar& mu,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        ChaumProof& proof
    );

private:
    Scalar challenge(
        const Scalar& mu,
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
