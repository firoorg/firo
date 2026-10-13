#ifndef FIRO_LIBSPARK_CLAIM_H
#define FIRO_LIBSPARK_CLAIM_H

#include "chaum.h"

namespace spark {

// Claims use the current componentwise proof for up to MAX_CHAUM_V2_INPUTS
// inputs, including claims about historical V1 transactions.
class Claim {
public:
    Claim(const GroupElement& F, const GroupElement& G, const GroupElement& H, const GroupElement& U);

    void prove(
        const Scalar& mu,
        const ChaumV2Context& context,
        const std::vector<unsigned char>& identifier,
        const std::vector<unsigned char>& message,
        const std::vector<Scalar>& x,
        const std::vector<Scalar>& y,
        const std::vector<Scalar>& z,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        ChaumProofV2& proof
    );
    bool verify(
        const Scalar& mu,
        const ChaumV2Context& context,
        const std::vector<unsigned char>& identifier,
        const std::vector<unsigned char>& message,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        const ChaumProofV2& proof
    );

private:
    static Scalar binding(
        const Scalar& mu,
        const std::vector<unsigned char>& identifier,
        const std::vector<unsigned char>& message
    );
    Chaum chaum;
};

}

#endif
