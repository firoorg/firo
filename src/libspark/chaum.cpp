#include "chaum.h"
#include "transcript.h"

namespace spark {

Chaum::Chaum(const GroupElement& F_, const GroupElement& G_, const GroupElement& H_, const GroupElement& U_):
    F(F_), G(G_), H(H_), U(U_) {
}

Scalar Chaum::challenge(
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

void Chaum::prove(
    const Scalar& mu,
    const std::vector<Scalar>& x,
    const std::vector<Scalar>& y,
    const std::vector<Scalar>& z,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    ChaumProof& proof
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

    Scalar c = challenge(mu, S, T, proof.A1, proof.A2);

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

bool Chaum::verify(
    const Scalar& mu,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    ChaumProof& proof
) {
    // Check proof semantics
    std::size_t n = S.size();
    if (!(T.size() == n && proof.A2.size() == n && proof.t1.size() == n)) {
        throw std::invalid_argument("Bad Chaum semantics!");
    }

    Scalar c = challenge(mu, S, T, proof.A1, proof.A2);
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

}
