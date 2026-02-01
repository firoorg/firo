#include "../../../test/test_bitcoin.h"
#include "../../../streams.h"
#include "../../../version.h"
#include "../type.h"
#include <boost/test/unit_test.hpp>

namespace spats
{
using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(spats_type_proof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(verify_complete)
{
    GroupElement E;
    E.randomize();
    GroupElement F;
    F.randomize();
    GroupElement G;
    G.randomize();
    GroupElement H;
    H.randomize();

    Scalar w;
    w.randomize();
    Scalar x;
    x.randomize();

    Scalar y;
    y.randomize();
    Scalar z;
    z.randomize();

    GroupElement C = E * w + F * x + G * y + H * z;

    TypeProof proof;

    TypeEquality type(E, F, G, H);
    type.prove(C, w, x, y, z, proof);

    BOOST_CHECK(type.verify(C, proof));
}

BOOST_AUTO_TEST_CASE(verify_complete_vector)
{
    const std::size_t n = 3;

    // Generator
    GroupElement E;
    E.randomize();
    GroupElement F;
    F.randomize();
    GroupElement G;
    G.randomize();
    GroupElement H;
    H.randomize();

    Scalar w;
    w.randomize();
    Scalar x;
    x.randomize();

    std::vector<Scalar> y;
    std::vector<Scalar> z;
    std::vector<GroupElement> C;

    for (std::size_t i = 0; i < n; i++) {
        y.emplace_back();
        y.back().randomize();
        z.emplace_back();
        z.back().randomize();

        C.emplace_back((E * w + F * x + G * y.back() + H * z.back()));
    }

    TypeProof proof;
    TypeEquality type(E, F, G, H);
    type.prove(C, w, x, y, z, proof);

    // Verify
    BOOST_CHECK(type.verify(C, proof));
}

BOOST_AUTO_TEST_CASE(bad_proofs)
{
    GroupElement E;
    E.randomize();
    GroupElement F;
    F.randomize();
    GroupElement G;
    G.randomize();
    GroupElement H;
    H.randomize();

    Scalar w;
    w.randomize();
    Scalar x;
    x.randomize();

    Scalar y;
    y.randomize();
    Scalar z;
    z.randomize();

    GroupElement C = E * w + F * x + G * y + H * z;

    TypeProof proof;

    TypeEquality type(E, F, G, H);
    type.prove(C, w, x, y, z, proof);

    // Bad C
    GroupElement bad_C;
    bad_C.randomize();
    BOOST_CHECK(!(type.verify(bad_C, proof)));

    // Bad A
    TypeProof bad_proof = proof;
    bad_proof.A.randomize();
    BOOST_CHECK(!(type.verify(C, bad_proof)));

    // Bad B
    bad_proof = proof;
    bad_proof.B.randomize();
    BOOST_CHECK(!(type.verify(C, bad_proof)));

    // Bad tw
    bad_proof = proof;
    bad_proof.tw.randomize();
    BOOST_CHECK(!(type.verify(C, bad_proof)));

    // Bad tx
    bad_proof = proof;
    bad_proof.tx.randomize();
    BOOST_CHECK(!(type.verify(C, bad_proof)));

    // Bad ty
    bad_proof = proof;
    bad_proof.ty.randomize();
    BOOST_CHECK(!(type.verify(C, bad_proof)));

    // Bad tz
    bad_proof = proof;
    bad_proof.tz.randomize();
    BOOST_CHECK(!(type.verify(C, bad_proof)));

    // Bad uy
    bad_proof = proof;
    bad_proof.uy.randomize();
    BOOST_CHECK(!(type.verify(C, bad_proof)));

    // Bad uz
    bad_proof = proof;
    bad_proof.uz.randomize();
    BOOST_CHECK(!(type.verify(C, bad_proof)));
}

// Test serialization roundtrip
BOOST_AUTO_TEST_CASE(serialization)
{
    GroupElement E, F, G, H;
    E.randomize();
    F.randomize();
    G.randomize();
    H.randomize();

    Scalar w, x, y, z;
    w.randomize();
    x.randomize();
    y.randomize();
    z.randomize();

    GroupElement C = E * w + F * x + G * y + H * z;

    TypeProof proof;
    TypeEquality type(E, F, G, H);
    type.prove(C, w, x, y, z, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    TypeProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.A == deserialized.A);
    BOOST_CHECK(proof.B == deserialized.B);
    BOOST_CHECK(proof.tw == deserialized.tw);
    BOOST_CHECK(proof.tx == deserialized.tx);
    BOOST_CHECK(proof.ty == deserialized.ty);
    BOOST_CHECK(proof.tz == deserialized.tz);
    BOOST_CHECK(proof.uy == deserialized.uy);
    BOOST_CHECK(proof.uz == deserialized.uz);

    // Deserialized proof should still verify
    BOOST_CHECK(type.verify(C, deserialized));
}

// Test that different type values fail verification (soundness)
BOOST_AUTO_TEST_CASE(different_types_fail)
{
    GroupElement E, F, G, H;
    E.randomize();
    F.randomize();
    G.randomize();
    H.randomize();

    // Common type values
    Scalar w1, x1;
    w1.randomize();
    x1.randomize();

    // Different type values
    Scalar w2, x2;
    w2.randomize();
    x2.randomize();

    Scalar y, z;
    y.randomize();
    z.randomize();

    // Commitment with type (w1, x1)
    GroupElement C1 = E * w1 + F * x1 + G * y + H * z;

    // Commitment with different type (w2, x2)
    GroupElement C2 = E * w2 + F * x2 + G * y + H * z;

    TypeProof proof;
    TypeEquality type(E, F, G, H);
    type.prove(C1, w1, x1, y, z, proof);

    // Proof for C1 should verify
    BOOST_CHECK(type.verify(C1, proof));

    // Proof for C1 should NOT verify for C2 (different type)
    BOOST_CHECK(!type.verify(C2, proof));
}

// Test vector with larger size
BOOST_AUTO_TEST_CASE(verify_large_vector)
{
    const std::size_t n = 10;

    GroupElement E, F, G, H;
    E.randomize();
    F.randomize();
    G.randomize();
    H.randomize();

    // Common asset type
    Scalar w, x;
    w.randomize();
    x.randomize();

    std::vector<Scalar> y;
    std::vector<Scalar> z;
    std::vector<GroupElement> C;

    for (std::size_t i = 0; i < n; i++) {
        y.emplace_back();
        y.back().randomize();
        z.emplace_back();
        z.back().randomize();

        C.emplace_back(E * w + F * x + G * y.back() + H * z.back());
    }

    TypeProof proof;
    TypeEquality type(E, F, G, H);
    type.prove(C, w, x, y, z, proof);

    BOOST_CHECK(type.verify(C, proof));
}

// Test that mixing types in vector fails
BOOST_AUTO_TEST_CASE(mixed_types_in_vector_fail)
{
    const std::size_t n = 3;

    GroupElement E, F, G, H;
    E.randomize();
    F.randomize();
    G.randomize();
    H.randomize();

    // First type
    Scalar w1, x1;
    w1.randomize();
    x1.randomize();

    std::vector<Scalar> y;
    std::vector<Scalar> z;
    std::vector<GroupElement> C;

    // Create commitments with same type
    for (std::size_t i = 0; i < n; i++) {
        y.emplace_back();
        y.back().randomize();
        z.emplace_back();
        z.back().randomize();

        C.emplace_back(E * w1 + F * x1 + G * y.back() + H * z.back());
    }

    TypeProof proof;
    TypeEquality type(E, F, G, H);
    type.prove(C, w1, x1, y, z, proof);

    // Valid proof should verify
    BOOST_CHECK(type.verify(C, proof));

    // Now create a mixed vector (different type for one element)
    Scalar w2, x2;
    w2.randomize();
    x2.randomize();

    std::vector<GroupElement> mixed_C;
    mixed_C.emplace_back(E * w1 + F * x1 + G * y[0] + H * z[0]);
    mixed_C.emplace_back(E * w2 + F * x2 + G * y[1] + H * z[1]); // Different type!
    mixed_C.emplace_back(E * w1 + F * x1 + G * y[2] + H * z[2]);

    // Proof for uniform type should NOT verify for mixed types
    BOOST_CHECK(!type.verify(mixed_C, proof));
}

// Test with zero value commitments
BOOST_AUTO_TEST_CASE(zero_value_commitment)
{
    GroupElement E, F, G, H;
    E.randomize();
    F.randomize();
    G.randomize();
    H.randomize();

    Scalar w, x;
    w.randomize();
    x.randomize();

    // y = 0 (zero value)
    Scalar y = Scalar(uint64_t(0));
    Scalar z;
    z.randomize();

    GroupElement C = E * w + F * x + G * y + H * z;

    TypeProof proof;
    TypeEquality type(E, F, G, H);
    type.prove(C, w, x, y, z, proof);

    BOOST_CHECK(type.verify(C, proof));
}

// Test proof cannot be reused
BOOST_AUTO_TEST_CASE(proof_not_reusable)
{
    GroupElement E, F, G, H;
    E.randomize();
    F.randomize();
    G.randomize();
    H.randomize();

    Scalar w, x;
    w.randomize();
    x.randomize();

    Scalar y1, z1, y2, z2;
    y1.randomize();
    z1.randomize();
    y2.randomize();
    z2.randomize();

    GroupElement C1 = E * w + F * x + G * y1 + H * z1;
    GroupElement C2 = E * w + F * x + G * y2 + H * z2;

    TypeProof proof;
    TypeEquality type(E, F, G, H);
    type.prove(C1, w, x, y1, z1, proof);

    // Proof for C1 verifies
    BOOST_CHECK(type.verify(C1, proof));

    // Proof for C1 should NOT verify for C2 (different y, z)
    BOOST_CHECK(!type.verify(C2, proof));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace spats