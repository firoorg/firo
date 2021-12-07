#include "schnorr.h"
#include "transcript.h"

namespace spark {

Schnorr::Schnorr(const GroupElement& G_):
    G(G_) {
}

Scalar Schnorr::challenge(
        const GroupElement& Y,
        const GroupElement& A) {
    Transcript transcript("SPARK_SCHNORR");
    transcript.add("G", G);
    transcript.add("Y", Y);
    transcript.add("A", A);

    return transcript.challenge("c");
}

void Schnorr::prove(const Scalar& y, const GroupElement& Y, SchnorrProof& proof) {
    // Check statement validity
    if (!(G*y == Y)) {
        throw std::invalid_argument("Bad Schnorr statement!");
    }

    Scalar r;
    r.randomize();
    GroupElement A = G*r;
    proof.c = challenge(Y, A);
    proof.t = r + proof.c*y;
}

bool Schnorr::verify(const GroupElement& Y, SchnorrProof& proof) {
    Scalar c = challenge(Y, G*proof.t + Y.inverse()*proof.c);

    return c == proof.c;
}

}
