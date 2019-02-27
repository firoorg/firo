#include <gtest/gtest.h>
#include <liblelantus/InnerProductProoveGenerator.h>
#include <liblelantus/InnerProductProofVerifier.h>

void generate(
        int n,
        std::vector <secp_primitives::GroupElement>& gens_g,
        std::vector <secp_primitives::GroupElement>& gens_h,
        std::vector <secp_primitives::Scalar>& a,
        std::vector <secp_primitives::Scalar>& b,
        secp_primitives::GroupElement& u_) {

    //creating generators g, h
    for (int i = 0; i < n; ++i) {
        secp_primitives::GroupElement g;
        secp_primitives::GroupElement h;
        g.randomize();
        gens_g.push_back(g);
        h.randomize();
        gens_h.push_back(h);
    }
    //creating group element u
    u_.randomize();
    //    //create a and b vectors
    for (int i = 0; i < n; ++i) {
        secp_primitives::Scalar a_;
        secp_primitives::Scalar b_;
        a_.randomize();
        b_.randomize();
        a.emplace_back(a_);
        b.emplace_back(b_);
    }
}

TEST(InnerProductProoveGeneratorTest, proof_verify)
{
    int n = 32;
    std::vector <secp_primitives::GroupElement> gens_g;
    std::vector <secp_primitives::GroupElement> gens_h;
    std::vector <secp_primitives::Scalar> a;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement u_;
    // generating needed objects
    generate(n, gens_g, gens_h, a, b, u_);
    //    creating generator vectors g, h
    zcoin_common::GeneratorVector <secp_primitives::Scalar, secp_primitives::GroupElement> g_(gens_g);
    zcoin_common::GeneratorVector <secp_primitives::Scalar, secp_primitives::GroupElement> h_(gens_h);
    secp_primitives::Scalar x;
    x.randomize();
    //    //creating proof genertor
    lelantus::InnerProductProoveGenerator<secp_primitives::Scalar, secp_primitives::GroupElement> prooveGenerator(g_, h_, u_);

    //////    //generating proof
    lelantus::InnerProductProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    prooveGenerator.generate_proof(a, b, x, proof);

    ////    //create verifier
    lelantus::InnerProductProofVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(g_, h_, u_, prooveGenerator.get_P());

    EXPECT_TRUE(verifier.verify(x, proof));

}

TEST(InnerProductProoveGeneratorTest, fake_proof_notVerify)
{
    int n = 32;
    std::vector <secp_primitives::GroupElement> gens_g;
    std::vector <secp_primitives::GroupElement> gens_h;
    std::vector <secp_primitives::Scalar> a;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement u_;
    // generating needed objects
    generate(n, gens_g, gens_h, a, b, u_);
    //    creating generator vectors g, h
    zcoin_common::GeneratorVector <secp_primitives::Scalar, secp_primitives::GroupElement> g_(gens_g);
    zcoin_common::GeneratorVector <secp_primitives::Scalar, secp_primitives::GroupElement> h_(gens_h);
    secp_primitives::Scalar x;
    x.randomize();
    //    //creating proof genertor
    lelantus::InnerProductProoveGenerator<secp_primitives::Scalar, secp_primitives::GroupElement> prooveGenerator(g_, h_, u_);

    //////    //generating proof
    lelantus::InnerProductProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    prooveGenerator.generate_proof(a, b, x, proof);

    ////    //create verifier with fake P
    secp_primitives::GroupElement P;
    P.randomize();
    lelantus::InnerProductProofVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(g_, h_, u_, P);

    EXPECT_FALSE(verifier.verify(x, proof));

}