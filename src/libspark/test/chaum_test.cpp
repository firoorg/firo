#include "../chaum.h"
#include "../transcript.h"
#include "../../streams.h"
#include "../../version.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

namespace {

void CheckV2Completeness(const std::size_t n)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();

    Scalar mu;
    mu.randomize();
    std::vector<Scalar> x(n), y(n), z(n);
    std::vector<GroupElement> S(n), T(n);
    for (std::size_t i = 0; i < n; ++i) {
        x[i].randomize();
        y[i].randomize();
        z[i].randomize();
        S[i] = F*x[i] + G*y[i] + H*z[i];
        T[i] = (U + G*y[i].negate())*x[i].inverse();
    }

    ChaumV2Context context;
    context.fee = 1234;
    context.transparent_value = 5678;
    context.serialized_outputs = {{0x01, 0x02}, {0x03, 0x04, 0x05}};

    Chaum chaum(F, G, H, U);
    ChaumProofV2 proof;
    chaum.prove_v2(mu, context, x, y, z, S, T, proof);
    BOOST_REQUIRE(chaum.verify_v2(mu, context, S, T, proof));

    CDataStream encoded(SER_NETWORK, PROTOCOL_VERSION);
    encoded << proof;
    ChaumProofV2 decoded;
    encoded >> decoded;
    BOOST_CHECK(chaum.verify_v2(mu, context, S, T, decoded));
    BOOST_CHECK(encoded.empty());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(spark_chaum_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(serialization)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();

    const std::size_t n = 3;

    Scalar mu;
    mu.randomize();
    std::vector<Scalar> x, y, z;
    x.resize(n);
    y.resize(n);
    z.resize(n);
    std::vector<GroupElement> S, T;
    S.resize(n);
    T.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        x[i].randomize();
        y[i].randomize();
        z[i].randomize();

        S[i] = F*x[i] + G*y[i] + H*z[i];
        T[i] = (U + G*y[i].negate())*x[i].inverse();
    }

    ChaumProofV1 proof;

    Chaum chaum(F, G, H, U);
    chaum.prove_v1(mu, x, y, z, S, T, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    ChaumProofV1 deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.A1 == deserialized.A1);
    BOOST_CHECK(proof.t2 == deserialized.t2);
    BOOST_CHECK(proof.t3 == deserialized.t3);
    for (std::size_t i = 0; i < n; i++) {
        BOOST_CHECK(proof.A2[i] == deserialized.A2[i]);
        BOOST_CHECK(proof.t1[i] == deserialized.t1[i]);
    }
}

BOOST_AUTO_TEST_CASE(completeness)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();

    const std::size_t n = 3;

    Scalar mu;
    mu.randomize();
    std::vector<Scalar> x, y, z;
    x.resize(n);
    y.resize(n);
    z.resize(n);
    std::vector<GroupElement> S, T;
    S.resize(n);
    T.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        x[i].randomize();
        y[i].randomize();
        z[i].randomize();

        S[i] = F*x[i] + G*y[i] + H*z[i];
        T[i] = (U + G*y[i].negate())*x[i].inverse();
    }

    ChaumProofV1 proof;

    Chaum chaum(F, G, H, U);
    chaum.prove_v1(mu, x, y, z, S, T, proof);

    BOOST_CHECK(chaum.verify_v1(mu, S, T, proof));
}

BOOST_AUTO_TEST_CASE(bad_proofs)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();

    const std::size_t n = 3;

    Scalar mu;
    mu.randomize();
    std::vector<Scalar> x, y, z;
    x.resize(n);
    y.resize(n);
    z.resize(n);
    std::vector<GroupElement> S, T;
    S.resize(n);
    T.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        x[i].randomize();
        y[i].randomize();
        z[i].randomize();

        S[i] = F*x[i] + G*y[i] + H*z[i];
        T[i] = (U + G*y[i].negate())*x[i].inverse();
    }

    ChaumProofV1 proof;

    Chaum chaum(F, G, H, U);
    chaum.prove_v1(mu, x, y, z, S, T, proof);

    // Bad mu
    Scalar evil_mu;
    evil_mu.randomize();
    BOOST_CHECK(!(chaum.verify_v1(evil_mu, S, T, proof)));

    // Bad S
    for (std::size_t i = 0; i < n; i++) {
        std::vector<GroupElement> evil_S(S);
        evil_S[i].randomize();
        BOOST_CHECK(!(chaum.verify_v1(mu, evil_S, T, proof)));
    }

    // Bad T
    for (std::size_t i = 0; i < n; i++) {
        std::vector<GroupElement> evil_T(T);
        evil_T[i].randomize();
        BOOST_CHECK(!(chaum.verify_v1(mu, S, evil_T, proof)));
    }

    // Bad A1
    ChaumProofV1 evil_proof = proof;
    evil_proof.A1.randomize();
    BOOST_CHECK(!(chaum.verify_v1(mu, S, T, evil_proof)));

    // Bad A2
    for (std::size_t i = 0; i < n; i++) {
        evil_proof = proof;
        evil_proof.A2[i].randomize();
        BOOST_CHECK(!(chaum.verify_v1(mu, S, T, evil_proof)));
    }

    // Bad t1
    for (std::size_t i = 0; i < n; i++) {
        evil_proof = proof;
        evil_proof.t1[i].randomize();
        BOOST_CHECK(!(chaum.verify_v1(mu, S, T, evil_proof)));
    }

    // Bad t2
    evil_proof = proof;
    evil_proof.t2.randomize();
    BOOST_CHECK(!(chaum.verify_v1(mu, S, T, evil_proof)));

    // Bad t3
    evil_proof = proof;
    evil_proof.t3.randomize();
    BOOST_CHECK(!(chaum.verify_v1(mu, S, T, evil_proof)));
}

BOOST_AUTO_TEST_CASE(empty_input_vectors_rejected)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();
    Scalar mu;
    mu.randomize();
    std::vector<GroupElement> S;
    std::vector<GroupElement> T;
    ChaumProofV1 proof;
    Chaum chaum(F, G, H, U);
    BOOST_CHECK_THROW(chaum.verify_v1(mu, S, T, proof), std::invalid_argument);
 }

BOOST_AUTO_TEST_CASE(single_input_verifier_accepts_valid_and_rejects_modified_proofs)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();

    Scalar mu, x, y, z;
    mu.randomize();
    x.randomize();
    y.randomize();
    z.randomize();
    const std::vector<GroupElement> S{F*x + G*y + H*z};
    const std::vector<GroupElement> T{
        (U + (G*y).inverse())*x.inverse()};

    Chaum chaum(F, G, H, U);
    ChaumProofV1 proof;
    chaum.prove_v1(mu, {x}, {y}, {z}, S, T, proof);
    BOOST_REQUIRE(chaum.verify_single_input(mu, S, T, proof));

    ChaumProofV1 badFirst = proof;
    do {
        badFirst.A1.randomize();
    } while (badFirst.A1 == proof.A1);
    BOOST_CHECK(!chaum.verify_single_input(mu, S, T, badFirst));

    ChaumProofV1 badSecond = proof;
    do {
        badSecond.A2[0].randomize();
    } while (badSecond.A2[0] == proof.A2[0]);
    BOOST_CHECK(!chaum.verify_single_input(mu, S, T, badSecond));
}

BOOST_AUTO_TEST_CASE(v2_completeness_and_serialization)
{
    CheckV2Completeness(1);
    CheckV2Completeness(2);
    CheckV2Completeness(5);
    CheckV2Completeness(MAX_CHAUM_V2_INPUTS);
}

BOOST_AUTO_TEST_CASE(v2_binds_context_and_each_statement)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();

    const std::size_t n = 2;
    Scalar mu;
    mu.randomize();
    std::vector<Scalar> x(n), y(n), z(n);
    std::vector<GroupElement> S(n), T(n);
    for (std::size_t i = 0; i < n; ++i) {
        x[i].randomize();
        y[i].randomize();
        z[i].randomize();
        S[i] = F*x[i] + G*y[i] + H*z[i];
        T[i] = (U + G*y[i].negate())*x[i].inverse();
    }

    ChaumV2Context context;
    context.fee = 11;
    context.transparent_value = 22;
    context.serialized_outputs = {{0xaa}, {0xbb}};
    context.extension_commitment = uint256S("01");
    context.serialized_cover_set_references = {0x01, 0xaa};

    Chaum chaum(F, G, H, U);
    ChaumProofV2 proof;
    chaum.prove_v2(mu, context, x, y, z, S, T, proof);
    BOOST_REQUIRE(chaum.verify_v2(mu, context, S, T, proof));

    ChaumV2Context changed = context;
    ++changed.fee;
    BOOST_CHECK(!chaum.verify_v2(mu, changed, S, T, proof));
    changed = context;
    ++changed.transparent_value;
    BOOST_CHECK(!chaum.verify_v2(mu, changed, S, T, proof));
    changed = context;
    changed.serialized_outputs[0][0] ^= 1;
    BOOST_CHECK(!chaum.verify_v2(mu, changed, S, T, proof));
    changed = context;
    changed.extension_commitment = uint256S("02");
    BOOST_CHECK(!chaum.verify_v2(mu, changed, S, T, proof));
    changed = context;
    changed.serialized_cover_set_references.back() ^= 1;
    BOOST_CHECK(!chaum.verify_v2(mu, changed, S, T, proof));

    for (std::size_t i = 0; i < n; ++i) {
        std::vector<GroupElement> changed_S = S;
        changed_S[i].randomize();
        BOOST_CHECK(!chaum.verify_v2(mu, context, changed_S, T, proof));

        std::vector<GroupElement> changed_T = T;
        changed_T[i].randomize();
        BOOST_CHECK(!chaum.verify_v2(mu, context, S, changed_T, proof));

        ChaumProofV2 changed_proof = proof;
        changed_proof.A1[i].randomize();
        BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, changed_proof));
        changed_proof = proof;
        changed_proof.A2[i].randomize();
        BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, changed_proof));
        changed_proof = proof;
        changed_proof.t1[i].randomize();
        BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, changed_proof));
        changed_proof = proof;
        changed_proof.t2[i].randomize();
        BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, changed_proof));
        changed_proof = proof;
        changed_proof.t3[i].randomize();
        BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, changed_proof));
    }

    Scalar offset;
    do {
        offset.randomize();
    } while (offset.isZero());
    ChaumProofV2 coupledResponses = proof;
    coupledResponses.t2[0] += offset;
    coupledResponses.t2[1] -= offset;
    BOOST_CHECK(!chaum.verify_v2(
        mu, context, S, T, coupledResponses));

    std::vector<GroupElement> reorderedS = S;
    std::vector<GroupElement> reorderedT = T;
    ChaumProofV2 reorderedProof = proof;
    std::swap(reorderedS[0], reorderedS[1]);
    std::swap(reorderedT[0], reorderedT[1]);
    std::swap(reorderedProof.A1[0], reorderedProof.A1[1]);
    std::swap(reorderedProof.A2[0], reorderedProof.A2[1]);
    std::swap(reorderedProof.t1[0], reorderedProof.t1[1]);
    std::swap(reorderedProof.t2[0], reorderedProof.t2[1]);
    std::swap(reorderedProof.t3[0], reorderedProof.t3[1]);
    BOOST_CHECK(!chaum.verify_v2(
        mu, context, reorderedS, reorderedT, reorderedProof));
}

// Regression test for the aggregate-soundness break that motivated V2.
//
// The deployed V1 verifier sums the input index out of both of its equations,
// so it only constrains sum(x_i) and sum(x_i*T_i). That lets a prover reuse a
// single owned coin across w inputs, publish forged tags T_i = k_i*T, and solve
// the resulting 2-by-w system for a non-diagonal witness. Neither published tag
// is the coin's canonical tag, so the duplicate-tag checks never fire and the
// balance proof credits the coin w times.
//
// V2 keeps each index in its own equation pair, which forces k_i = 1 and
// collapses the forgery back onto the real tag. This test builds the forgery
// explicitly and pins both halves: V1 accepts it, V2 does not.
BOOST_AUTO_TEST_CASE(v2_rejects_non_diagonal_aggregate_witness)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();

    Scalar mu;
    mu.randomize();

    // One honestly owned coin, spent twice.
    Scalar s, y0, z0;
    s.randomize();
    y0.randomize();
    z0.randomize();
    const GroupElement T_coin = (U + G*y0.negate())*s.inverse();

    // Present the one coin as both inputs. The serial and blind agree, but the
    // H-offsets differ, so the two published statements are distinct while the
    // serial relation still forces x_0 = x_1 = s.
    const std::size_t n = 2;
    std::vector<Scalar> z(n);
    z[0] = z0;
    do {
        z[1].randomize();
    } while (z[1] == z0);
    std::vector<GroupElement> S(n);
    for (std::size_t i = 0; i < n; ++i) {
        S[i] = F*s + G*y0 + H*z[i];
    }
    BOOST_REQUIRE(S[0] != S[1]);

    // Forged tags: scalar multiples of the canonical tag, neither equal to it.
    std::vector<Scalar> k(n);
    k[0] = Scalar(uint64_t(3));
    k[1] = Scalar(uint64_t(7));
    std::vector<GroupElement> T(n);
    for (std::size_t i = 0; i < n; ++i) {
        T[i] = T_coin*k[i];
    }
    BOOST_REQUIRE(T[0] != T_coin);
    BOOST_REQUIRE(T[1] != T_coin);
    BOOST_REQUIRE(T[0] != T[1]);

    Chaum chaum(F, G, H, U);

    // Build a V1 transcript directly from the forged witness. The V1 prover
    // enforces the componentwise relation up front, so the forgery has to be
    // assembled the way a real attacker would: honest-shaped commitments over
    // the aggregate, then responses derived from the challenge.
    std::vector<Scalar> r(n), sc(n), t(n);
    ChaumProofV1 forged;
    forged.A2.resize(n);
    Scalar r_sum, s_sum, t_sum;
    for (std::size_t i = 0; i < n; ++i) {
        r[i].randomize();
        sc[i].randomize();
        t[i].randomize();
        forged.A2[i] = T[i]*r[i] + G*sc[i];
        r_sum += r[i];
        s_sum += sc[i];
        t_sum += t[i];
    }
    forged.A1 = F*r_sum + G*s_sum + H*t_sum;

    // The V1 challenge is a pure function of the public statement, so the
    // attacker can recompute it offline and answer with the non-diagonal
    // witness. This mirrors Chaum::challenge_v1 exactly.
    Transcript transcript(LABEL_TRANSCRIPT_CHAUM);
    transcript.add("F", F);
    transcript.add("G", G);
    transcript.add("H", H);
    transcript.add("U", U);
    transcript.add("mu", mu);
    transcript.add("S", S);
    transcript.add("T", T);
    transcript.add("A1", forged.A1);
    transcript.add("A2", forged.A2);
    const Scalar c = transcript.challenge("c");

    // The V1 verifier weights statement column j by c^(j+1), so the aggregate
    // system can only be solved once the challenge is known. Its two rows are
    //   (I)  sum_i t1_i     = sum_i r_i + (sum_j cp_j)*s
    //   (II) sum_i k_i*t1_i = sum_i k_i*r_i + (sum_j cp_j)*s
    // where the right-hand sides come from expanding the honest openings of the
    // duplicated coin. Any k_0 != k_1 makes the 2x2 matrix invertible, which is
    // precisely the degree of freedom the aggregation leaves open.
    std::vector<Scalar> cp(n);
    cp[0] = c;
    for (std::size_t i = 1; i < n; ++i) {
        cp[i] = cp[i-1]*c;
    }
    Scalar cp_sum;
    for (std::size_t i = 0; i < n; ++i) {
        cp_sum += cp[i];
    }

    Scalar row1, row2;
    for (std::size_t i = 0; i < n; ++i) {
        row1 += r[i];
        row2 += k[i]*r[i];
    }
    row1 += cp_sum*s;
    row2 += cp_sum*s;

    const Scalar det = k[1] + k[0].negate();
    const Scalar t1_1 = (row2 + (k[0]*row1).negate())*det.inverse();
    const Scalar t1_0 = row1 + t1_1.negate();

    forged.t1.resize(n);
    forged.t1[0] = t1_0;
    forged.t1[1] = t1_1;
    forged.t2 = s_sum + cp_sum*y0;
    forged.t3 = t_sum;
    for (std::size_t i = 0; i < n; ++i) {
        forged.t3 += cp[i]*z[i];
    }

    // The forgery is genuinely non-diagonal: neither response is the honest
    // opening the coin's own serial would produce.
    BOOST_REQUIRE(forged.t1[0] != r[0] + cp[0]*s);
    BOOST_REQUIRE(forged.t1[1] != r[1] + cp[1]*s);

    // The vulnerability is real: the deployed verifier accepts the forgery.
    // BOOST_REQUIRE, not BOOST_CHECK -- if this ever stops holding, the V2
    // assertions below would pass vacuously against a proof that forges
    // nothing, and the test would silently lose all of its value.
    BOOST_REQUIRE(chaum.verify_v1(mu, S, T, forged));

    // V2 must reject the same statement. Because each index carries its own
    // equation pair, a valid V2 proof would require k_i = 1 for every i, which
    // contradicts the forged tags -- so no V2 witness exists at all.
    ChaumV2Context context;
    context.fee = 0;
    context.transparent_value = 0;

    // Even the honest opening of the duplicated coin cannot prove the forged
    // statement under V2: the per-index tag equation U = T_i*x_i + G*y_i fails
    // for every k_i != 1, so prove_v2 rejects its own inputs up front.
    std::vector<Scalar> honest_x(n, s), y(n, y0);
    BOOST_CHECK_THROW(
        {
            ChaumProofV2 impossible;
            chaum.prove_v2(mu, context, honest_x, y, z, S, T, impossible);
        },
        std::invalid_argument);

    // And a transplanted proof over the forged tags does not verify either.
    ChaumProofV2 transplanted;
    transplanted.A1.assign(n, forged.A1);
    transplanted.A2 = forged.A2;
    transplanted.t1 = forged.t1;
    transplanted.t2.assign(n, forged.t2);
    transplanted.t3.assign(n, forged.t3);
    BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, transplanted));
}

BOOST_AUTO_TEST_CASE(v2_rejects_bad_dimensions_before_verification)
{
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();
    Scalar mu;
    mu.randomize();
    ChaumV2Context context;
    Chaum chaum(F, G, H, U);
    ChaumProofV2 proof;

    BOOST_CHECK(!chaum.verify_v2(mu, context, {}, {}, proof));

    std::vector<GroupElement> S(MAX_CHAUM_V2_INPUTS + 1);
    std::vector<GroupElement> T(MAX_CHAUM_V2_INPUTS + 1);
    BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, proof));
}

BOOST_AUTO_TEST_SUITE_END()

}
