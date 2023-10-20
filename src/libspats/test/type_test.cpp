#include "../../test/test_bitcoin.h"
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
BOOST_AUTO_TEST_SUITE_END()

} // namespace spats