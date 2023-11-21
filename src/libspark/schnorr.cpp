#include "schnorr.h"
#include "transcript.h"

namespace spark {

Schnorr::Schnorr(const GroupElement& G_):
    G(G_) {
}

Scalar Schnorr::challenge(
        const std::vector<GroupElement>& Y,
        const GroupElement& A) {
    Transcript transcript(LABEL_TRANSCRIPT_SCHNORR);
    transcript.add("G", G);
    transcript.add("Y", Y);
    transcript.add("A", A);

    return transcript.challenge("c");
}

void Schnorr::prove(const Scalar& y, const GroupElement& Y, SchnorrProof& proof) {
    const std::vector<Scalar> y_vector = { y };
    const std::vector<GroupElement> Y_vector = { Y };
    prove(y_vector, Y_vector, proof);
}

void Schnorr::prove(const std::vector<Scalar>& y, const std::vector<GroupElement>& Y, SchnorrProof& proof) {
    const std::size_t n = y.size();

    // Check statement validity
    if (y.size() != Y.size()) {
        throw std::invalid_argument("Bad Schnorr statement!");
    }

    for (std::size_t i = 0; i < n; i++) {
        if (G*y[i] != Y[i]) {
            throw std::invalid_argument("Bad Schnorr statement!");
        }
    }

    Scalar r;
    r.randomize();
    proof.A = G*r;

    const Scalar c = challenge(Y, proof.A);
    Scalar c_power(c);

    proof.t = r;
    for (std::size_t i = 0; i < n; i++) {
        if (c_power.isZero()) {
            throw std::invalid_argument("Unexpected challenge!");
        }

        proof.t += y[i].negate()*c_power;
        c_power *= c;
    }
}

bool Schnorr::verify(const GroupElement& Y, const SchnorrProof& proof) {
    const std::vector<GroupElement> Y_vector = { Y };
    return verify(Y_vector, proof);
}

bool Schnorr::verify(const std::vector<GroupElement>& Y, const SchnorrProof& proof) {
    const std::size_t n = Y.size();

    std::vector<GroupElement> points;
    points.reserve(n + 2);
    std::vector<Scalar> scalars;
    scalars.reserve(n + 2);

    points.emplace_back(G);
    scalars.emplace_back(proof.t);
    points.emplace_back(proof.A);
    scalars.emplace_back(Scalar(uint64_t(1)).negate());
    
    const Scalar c = challenge(Y, proof.A);
    Scalar c_power(c);
    for (std::size_t i = 0; i < n; i++) {
        if (c_power.isZero()) {
            throw std::invalid_argument("Unexpected challenge!");
        }

        points.emplace_back(Y[i]);
        scalars.emplace_back(c_power);
        c_power *= c;
    }

    MultiExponent result(points, scalars);
    return result.get_multiple().isInfinity();
}

}
