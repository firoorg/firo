#include "claim.h"
#include "transcript.h"

namespace spark {

Claim::Claim(const GroupElement& F, const GroupElement& G, const GroupElement& H, const GroupElement& U):
    chaum(F, G, H, U) {
}

Scalar Claim::binding(
    const Scalar& mu,
    const std::vector<unsigned char>& identifier,
    const std::vector<unsigned char>& message
) {
    // Separate claims from authorizing proofs without duplicating the V2
    // proof equations. Chaum binds this scalar and the complete statement.
    Transcript transcript(LABEL_TRANSCRIPT_CLAIM);
    transcript.add("mu", mu);
    transcript.add("identifier", identifier);
    transcript.add("message", message);
    return transcript.challenge("mu");
}

void Claim::prove(
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
) {
    chaum.prove_v2(binding(mu, identifier, message), context, x, y, z, S, T, proof);
}

bool Claim::verify(
    const Scalar& mu,
    const ChaumV2Context& context,
    const std::vector<unsigned char>& identifier,
    const std::vector<unsigned char>& message,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    const ChaumProofV2& proof
) {
    return chaum.verify_v2(binding(mu, identifier, message), context, S, T, proof);
}

}
