#include "base_asset.h"
#include "transcript.h"

namespace spats {

BaseAsset::BaseAsset(const GroupElement& G_,const GroupElement& H_):
    G(G_),H(H_) {
}

Scalar BaseAsset::challenge(
        const std::vector<GroupElement>& C,
        const GroupElement& A) {
    Transcript transcript(LABEL_TRANSCRIPT_BASE);
    transcript.add("G", G);
    transcript.add("H", H);
    transcript.add("C", C);
    transcript.add("A", A);

    return transcript.challenge("c");
}

void BaseAsset::prove(const Scalar& y,const Scalar& z, const GroupElement& C, BaseAssetProof& proof) {
    const std::vector<Scalar> y_vector = { y };
    const std::vector<Scalar> z_vector = { z };

    const std::vector<GroupElement> C_vector = { C };
    prove(y_vector,z_vector, C_vector, proof);
}

void BaseAsset::prove(const std::vector<Scalar>& y,const std::vector<Scalar>& z, const std::vector<GroupElement>& C, BaseAssetProof& proof) {
    const std::size_t n = y.size();

    // Check statement validity
    if (y.size() != z.size() && y.size() != C.size()) {
        throw std::invalid_argument("Bad BaseAsset statement!");
    }

    for (std::size_t i = 0; i < n; i++) {
        if (G*y[i]+H*z[i] != C[i]) {
            throw std::invalid_argument("Bad BaseAsset statement!");
        }
    }

    Scalar ry;
    Scalar rz;
    ry.randomize();
    rz.randomize();
    proof.A = G*ry+H*rz;

    const Scalar c = challenge(C, proof.A);
    Scalar c_power(c);

    proof.ty = ry;
    proof.tz = rz;
    for (std::size_t i = 0; i < n; i++) {
        proof.ty += y[i].negate()*c_power;
        proof.tz += z[i].negate()*c_power;
        c_power *= c;
    }
}

bool BaseAsset::verify(const GroupElement& C, const BaseAssetProof& proof) {
    const std::vector<GroupElement> C_vector = { C };
    return verify(C_vector, proof);
}

bool BaseAsset::verify(const std::vector<GroupElement>& C, const BaseAssetProof& proof) {
    const std::size_t n = C.size();

    std::vector<GroupElement> points;
    points.reserve(n + 2);
    std::vector<Scalar> scalars;
    scalars.reserve(n + 2);

    points.emplace_back(G);
    scalars.emplace_back(proof.ty);
    points.emplace_back(H);
    scalars.emplace_back(proof.tz);
    points.emplace_back(proof.A);
    scalars.emplace_back(Scalar(uint64_t(1)).negate());
    
    const Scalar c = challenge(C, proof.A);
    Scalar c_power(c);
    for (std::size_t i = 0; i < n; i++) {
        points.emplace_back(C[i]);
        scalars.emplace_back(c_power);
        c_power *= c;
    }

    MultiExponent result(points, scalars);
    return result.get_multiple().isInfinity();
}

}
