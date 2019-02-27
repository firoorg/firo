#include <gtest/gtest.h>
#include <liblelantus/SchnorrProof.h>
#include <liblelantus/SchnorrProver.h>
#include <liblelantus/SchnorrVerifier.h>
using  namespace secp_primitives;
using  namespace lelantus;

TEST(schnorr_test, proof_verify)
{
    GroupElement g, h;
    g.randomize();
    h.randomize();
    Scalar P, T;
    P.randomize();
    T.randomize();
    GroupElement y = LelantusPrimitives<Scalar, GroupElement>::commit(g, P, h, T);
    SchnorrProver<Scalar, GroupElement> prover(g, h);
    SchnorrProof<Scalar, GroupElement> proof;
    prover.proof(P, T, proof);
    SchnorrVerifier<Scalar, GroupElement> verifier(g, h);
    EXPECT_TRUE(verifier.verify(y ,proof));
}

TEST(schnorr_test, proof_serialize_deserialize_verify)
{
    GroupElement g, h;
    g.randomize();
    h.randomize();
    Scalar P, T;
    P.randomize();
    T.randomize();
    GroupElement y = LelantusPrimitives<Scalar, GroupElement>::commit(g, P, h, T);
    SchnorrProver<Scalar, GroupElement> prover(g, h);
    SchnorrProof<Scalar, GroupElement> proof;
    prover.proof(P, T, proof);

    unsigned char buffer[proof.memoryRequired()];
    proof.serialize(buffer);
    SchnorrProof<Scalar, GroupElement> new_proof;
    new_proof.deserialize(buffer);
    SchnorrVerifier<Scalar, GroupElement> verifier(g, h);
    EXPECT_TRUE(verifier.verify(y ,new_proof));
}