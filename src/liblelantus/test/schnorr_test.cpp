#include "../schnorr_proof.h"
#include "../schnorr_prover.h"
#include "../schnorr_verifier.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(lelantus_schnorr_proof_tests)

BOOST_AUTO_TEST_CASE(prove_verify)
{
    secp_primitives::GroupElement g, h;
    g.randomize();
    h.randomize();
    secp_primitives::Scalar P, T;
    P.randomize();
    T.randomize();
    secp_primitives::GroupElement y = lelantus::LelantusPrimitives<Scalar, GroupElement>::commit(g, P, h, T);
    lelantus::SchnorrProver<Scalar, GroupElement> prover(g, h);
    lelantus::SchnorrProof<Scalar, GroupElement> proof;
    prover.proof(P, T, proof);
    lelantus::SchnorrVerifier<Scalar, GroupElement> verifier(g, h);
    BOOST_CHECK(verifier.verify(y ,proof));
}

BOOST_AUTO_TEST_CASE(fake_prove_not_verify)
{
    secp_primitives::GroupElement g, h;
    g.randomize();
    h.randomize();
    secp_primitives::Scalar P, T;
    P.randomize();
    T.randomize();
    secp_primitives::GroupElement y;
    y.randomize();
    lelantus::SchnorrProver<Scalar, GroupElement> prover(g, h);
    lelantus::SchnorrProof<Scalar, GroupElement> proof;
    prover.proof(P, T, proof);
    lelantus::SchnorrVerifier<Scalar, GroupElement> verifier(g, h);
    BOOST_CHECK(!verifier.verify(y ,proof));
}

BOOST_AUTO_TEST_SUITE_END()