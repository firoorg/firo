#ifndef FIRO_LIBSPARK_CHAUM_H
#define FIRO_LIBSPARK_CHAUM_H

#include "chaum_proof.h"
#include "uint256.h"
#include <secp256k1/include/MultiExponent.h>

namespace spark {

struct ChaumV2Context {
    uint64_t fee = 0;
    uint64_t transparent_value = 0;
    std::vector<std::vector<unsigned char>> serialized_outputs;
    uint256 extension_commitment{};
    std::vector<unsigned char> serialized_cover_set_references;
};

class Chaum {
public:
    Chaum(const GroupElement& F, const GroupElement& G, const GroupElement& H, const GroupElement& U);

    void prove_v1(
        const Scalar& mu,
        const std::vector<Scalar>& x,
        const std::vector<Scalar>& y,
        const std::vector<Scalar>& z,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        ChaumProofV1& proof
    );
    // Original verification retained for pre-activation historical blocks.
    bool verify_v1(
        const Scalar& mu,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        ChaumProofV1& proof
    );
    bool verify_single_input(
        const Scalar& mu,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        ChaumProofV1& proof
    );

    void prove_v2(
        const Scalar& mu,
        const ChaumV2Context& context,
        const std::vector<Scalar>& x,
        const std::vector<Scalar>& y,
        const std::vector<Scalar>& z,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        ChaumProofV2& proof
    );
    bool verify_v2(
        const Scalar& mu,
        const ChaumV2Context& context,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        const ChaumProofV2& proof
    );

private:
    Scalar challenge_v1(
        const Scalar& mu,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        const GroupElement& A1,
        const std::vector<GroupElement>& A2
    );
    Scalar challenge_v2(
        const Scalar& mu,
        const ChaumV2Context& context,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        const std::vector<GroupElement>& A1,
        const std::vector<GroupElement>& A2
    );
    const GroupElement& F;
    const GroupElement& G;
    const GroupElement& H;
    const GroupElement& U;
};

}

#endif
