#include "chaum.h"
#include "transcript.h"

namespace spark {

Chaum::Chaum(const GroupElement& F_, const GroupElement& G_, const GroupElement& H_, const GroupElement& U_):
    F(F_), G(G_), H(H_), U(U_) {
}

namespace {

std::vector<unsigned char> EncodeUint64LE(uint64_t value)
{
    std::vector<unsigned char> encoded(8);
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        encoded[i] = static_cast<unsigned char>(value & 0xff);
        value >>= 8;
    }
    return encoded;
}

} // namespace

Scalar Chaum::challenge_v1(
    const Scalar& mu,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    const GroupElement& A1,
    const std::vector<GroupElement>& A2
) {
    Transcript transcript(LABEL_TRANSCRIPT_CHAUM);
    transcript.add("F", F);
    transcript.add("G", G);
    transcript.add("H", H);
    transcript.add("U", U);
    transcript.add("mu", mu);
    transcript.add("S", S);
    transcript.add("T", T);
    transcript.add("A1", A1);
    transcript.add("A2", A2);

    return transcript.challenge("c");
}

void Chaum::prove_v1(
    const Scalar& mu,
    const std::vector<Scalar>& x,
    const std::vector<Scalar>& y,
    const std::vector<Scalar>& z,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    ChaumProofV1& proof
) {
    // Check statement validity
    std::size_t n = x.size();
    if (!(y.size() == n && z.size() == n && S.size() == n && T.size() == n)) {
        throw std::invalid_argument("Bad Chaum statement!");
    }
    for (std::size_t i = 0; i < n; i++) {
        if (!(F*x[i] + G*y[i] + H*z[i] == S[i] && T[i]*x[i] + G*y[i] == U)) {
            throw std::invalid_argument("Bad Chaum statement!");
        }
    }

    std::vector<Scalar> r;
    r.resize(n);
    std::vector<Scalar> s;
    s.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        r[i].randomize();
        s[i].randomize();
    }
    Scalar t;
    t.randomize();

    proof.A1 = H*t;
    proof.A2.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        proof.A1 += F*r[i] + G*s[i];
        proof.A2[i] = T[i]*r[i] + G*s[i];
    }

    Scalar c = challenge_v1(mu, S, T, proof.A1, proof.A2);

    proof.t1.resize(n);
    proof.t3 = t;
    Scalar c_power(c);
    for (std::size_t i = 0; i < n; i++) {
        if (c_power.isZero()) {
            throw std::invalid_argument("Unexpected challenge!");
        }
        proof.t1[i] = r[i] + c_power*x[i];
        proof.t2 += s[i] + c_power*y[i];
        proof.t3 += c_power*z[i];
        c_power *= c;
    }
}

bool Chaum::verify_v1(
    const Scalar& mu,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    ChaumProofV1& proof
) {
    // Check proof semantics
    std::size_t n = S.size();
    if (n == 0 || !(T.size() == n && proof.A2.size() == n && proof.t1.size() == n)) {
        throw std::invalid_argument("Bad Chaum semantics!");
    }
    for (std::size_t i = 0; i < n; i++) {
        if (S[i].isInfinity()) {
            throw std::invalid_argument("Bad Chaum input!");
        }
        if (T[i].isInfinity()) {
            throw std::invalid_argument("Bad Chaum input!");
        }
    }

    Scalar c = challenge_v1(mu, S, T, proof.A1, proof.A2);
    if (c.isZero()) {
        throw std::invalid_argument("Unexpected challenge!");
    }
    std::vector<Scalar> c_powers;
    c_powers.emplace_back(c);
    for (std::size_t i = 1; i < n; i++) {
        c_powers.emplace_back(c_powers[i-1]*c);
        if (c_powers[i].isZero()) {
            throw std::invalid_argument("Unexpected challenge!");
        }
    }

    // Weight the verification equations
    Scalar w;
    while (w.isZero()) {
        w.randomize();
    }

    std::vector<Scalar> scalars;
    std::vector<GroupElement> points;
    scalars.reserve(3*n + 5);
    points.reserve(3*n + 5);

    // F
    Scalar F_scalar;
    for (std::size_t i = 0; i < n; i++) {
        F_scalar -= proof.t1[i];
    }
    scalars.emplace_back(F_scalar);
    points.emplace_back(F);

    // G
    scalars.emplace_back(proof.t2.negate() - w*proof.t2);
    points.emplace_back(G);

    // H
    scalars.emplace_back(proof.t3.negate());
    points.emplace_back(H);

    // U
    Scalar U_scalar;
    for (std::size_t i = 0; i < n; i++) {
        U_scalar += c_powers[i];
    }
    U_scalar *= w;
    scalars.emplace_back(U_scalar);
    points.emplace_back(U);

    // A1
    scalars.emplace_back(Scalar((uint64_t) 1));
    points.emplace_back(proof.A1);

    // {A2}
    GroupElement A2_sum = proof.A2[0];
    for (std::size_t i = 1; i < n; i++) {
        A2_sum += proof.A2[i];
    }
    scalars.emplace_back(w);
    points.emplace_back(A2_sum);

    // {S}
    for (std::size_t i = 0; i < n; i++) {
        scalars.emplace_back(c_powers[i]);
        points.emplace_back(S[i]);
    }

    // {T}
    for (std::size_t i = 0; i < n; i++) {
        scalars.emplace_back(w.negate()*proof.t1[i]);
        points.emplace_back(T[i]);
    }

    secp_primitives::MultiExponent multiexp(points, scalars);
    // merged equalities and doing check in one multiexponentation,
    // for weighting we use random w
    return multiexp.get_multiple().isInfinity();
}

bool Chaum::verify_single_input(
    const Scalar& mu,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    ChaumProofV1& proof
) {
    // The current path accepts only the single-input statement shape.
    // Pre-activation blocks use the explicit historical compatibility path.
    if (S.size() != 1 || T.size() != 1) {
        return false;
    }
    if (proof.A2.size() != 1 || proof.t1.size() != 1 ||
        S[0].isInfinity() || T[0].isInfinity()) {
        throw std::invalid_argument("Bad Chaum single-input semantics!");
    }

    const Scalar c = challenge_v1(mu, S, T, proof.A1, proof.A2);
    if (c.isZero()) {
        throw std::invalid_argument("Unexpected challenge!");
    }

    const GroupElement firstLeft = proof.A1 + S[0]*c;
    const GroupElement firstRight =
        F*proof.t1[0] + G*proof.t2 + H*proof.t3;
    if (firstLeft != firstRight) {
        return false;
    }

    const GroupElement secondLeft = proof.A2[0] + U*c;
    const GroupElement secondRight = T[0]*proof.t1[0] + G*proof.t2;
    return secondLeft == secondRight;
}

Scalar Chaum::challenge_v2(
    const Scalar& mu,
    const ChaumV2Context& context,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    const std::vector<GroupElement>& A1,
    const std::vector<GroupElement>& A2
) {
    Transcript transcript(LABEL_TRANSCRIPT_CHAUM_V2);
    transcript.add("version", std::vector<unsigned char>{2});
    transcript.add("input_count", EncodeUint64LE(S.size()));
    transcript.add("F", F);
    transcript.add("G", G);
    transcript.add("H", H);
    transcript.add("U", U);
    transcript.add("mu", mu);
    transcript.add("S", S);
    transcript.add("T", T);
    transcript.add("A1", A1);
    transcript.add("A2", A2);
    transcript.add("outputs", context.serialized_outputs);
    transcript.add("fee", EncodeUint64LE(context.fee));
    transcript.add("transparent_value", EncodeUint64LE(context.transparent_value));
    return transcript.challenge("c");
}

void Chaum::prove_v2(
    const Scalar& mu,
    const ChaumV2Context& context,
    const std::vector<Scalar>& x,
    const std::vector<Scalar>& y,
    const std::vector<Scalar>& z,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    ChaumProofV2& proof
) {
    const std::size_t n = x.size();
    if (n == 0 || n > MAX_CHAUM_V2_INPUTS ||
        y.size() != n || z.size() != n || S.size() != n || T.size() != n) {
        throw std::invalid_argument("Bad Chaum V2 statement");
    }
    for (std::size_t i = 0; i < n; ++i) {
        if (S[i].isInfinity() || T[i].isInfinity() ||
            F*x[i] + G*y[i] + H*z[i] != S[i] ||
            T[i]*x[i] + G*y[i] != U) {
            throw std::invalid_argument("Bad Chaum V2 statement");
        }
    }

    std::vector<Scalar> r(n), s(n), t(n);
    proof.A1.resize(n);
    proof.A2.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
        r[i].randomize();
        s[i].randomize();
        t[i].randomize();
        proof.A1[i] = F*r[i] + G*s[i] + H*t[i];
        proof.A2[i] = T[i]*r[i] + G*s[i];
    }

    const Scalar c = challenge_v2(mu, context, S, T, proof.A1, proof.A2);
    if (c.isZero()) {
        throw std::invalid_argument("Unexpected Chaum V2 challenge");
    }

    proof.t1.resize(n);
    proof.t2.resize(n);
    proof.t3.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
        proof.t1[i] = r[i] + c*x[i];
        proof.t2[i] = s[i] + c*y[i];
        proof.t3[i] = t[i] + c*z[i];
    }
}

bool Chaum::verify_v2(
    const Scalar& mu,
    const ChaumV2Context& context,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    const ChaumProofV2& proof
) {
    const std::size_t n = S.size();
    if (n == 0 || n > MAX_CHAUM_V2_INPUTS || T.size() != n ||
        proof.A1.size() != n || proof.A2.size() != n ||
        proof.t1.size() != n || proof.t2.size() != n || proof.t3.size() != n) {
        return false;
    }
    for (std::size_t i = 0; i < n; ++i) {
        if (S[i].isInfinity() || T[i].isInfinity() ||
            proof.A1[i].isInfinity() || proof.A2[i].isInfinity()) {
            return false;
        }
    }

    const Scalar c = challenge_v2(mu, context, S, T, proof.A1, proof.A2);
    if (c.isZero()) {
        return false;
    }

    // Check all 2*n equations directly. This correctness-oriented verifier
    // deliberately avoids probabilistic batching until independently derived
    // coefficients and the final transcript have received cryptographic review.
    for (std::size_t i = 0; i < n; ++i) {
        if (proof.A1[i] + S[i]*c !=
                F*proof.t1[i] + G*proof.t2[i] + H*proof.t3[i] ||
            proof.A2[i] + U*c != T[i]*proof.t1[i] + G*proof.t2[i]) {
            return false;
        }
    }
    return true;
}

}
