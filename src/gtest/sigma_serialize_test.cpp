#include <gtest/gtest.h>
#include <libzerocoin/sigma/SigmaPlusProver.h>
#include <libzerocoin/sigma/SigmaPlusVerifier.h>

TEST(sigma_serialize_tests, group_element_serialize)
{
    secp_primitives::GroupElement initial;
    initial.randomize();
    unsigned char buffer [initial.memoryRequired()];
    initial.serialize(buffer);
    secp_primitives::GroupElement resulted;
    resulted.deserialize(buffer);
    EXPECT_TRUE(initial == resulted);
}

TEST(sigma_serialize_tests, group_element_serialize_infinity)
{
    secp_primitives::GroupElement initial;
    unsigned char buffer [initial.memoryRequired()];
    initial.serialize(buffer);
    secp_primitives::GroupElement resulted;
    resulted.deserialize(buffer);
    EXPECT_TRUE(initial == resulted);
}

TEST(sigma_serialize_tests, scalar_serialize)
{
    secp_primitives::Scalar initial;
    initial.randomize();
    unsigned char buffer [initial.memoryRequired()];
    initial.serialize(buffer);
    secp_primitives::Scalar resulted;
    resulted.deserialize(buffer);
    EXPECT_TRUE(initial == resulted);
}

TEST(sigma_serialize_tests, proof_serialize)
{
    int N = 16;
    int n = 4;
    int index = 0;

    int m = (int)(log(N) / log(n));;

    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for(int i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;
    for(int i = 0; i < N; ++i){
        if(i == index){
            secp_primitives::GroupElement c;
            secp_primitives::Scalar zero(uint64_t(0));
            c = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, zero, h_gens[0], r);
            commits.push_back(c);

        }
        else{
            commits.push_back(secp_primitives::GroupElement());
            commits[i].randomize();
        }
    }

    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> initial_proof;

    prover.proof(commits, index, r, initial_proof);

    unsigned char buffer [initial_proof.memoryRequired()];
    initial_proof.serialize(buffer);
    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> resulted_proof;
    resulted_proof.deserialize(buffer, n, m);

    EXPECT_TRUE(initial_proof.B_ == resulted_proof.B_);
    EXPECT_TRUE(initial_proof.r1Proof_.A_ == resulted_proof.r1Proof_.A_);
    EXPECT_TRUE(initial_proof.r1Proof_.C_ == resulted_proof.r1Proof_.C_);
    EXPECT_TRUE(initial_proof.r1Proof_.D_ == resulted_proof.r1Proof_.D_);
    EXPECT_TRUE(initial_proof.r1Proof_.f_ == resulted_proof.r1Proof_.f_);
    EXPECT_TRUE(initial_proof.r1Proof_.ZA_ == resulted_proof.r1Proof_.ZA_);
    EXPECT_TRUE(initial_proof.r1Proof_.ZC_ == resulted_proof.r1Proof_.ZC_);
    EXPECT_TRUE(initial_proof.Gk_ == resulted_proof.Gk_);
    EXPECT_TRUE(initial_proof.z_ == resulted_proof.z_);
}