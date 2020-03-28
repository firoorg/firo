#include "../innerproduct_proof_generator.h"
#include "../innerproduct_proof_verifier.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(lelantus_inner_product_tests)

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

BOOST_AUTO_TEST_CASE(prove_verify)
{
    int n = 32;
    std::vector <secp_primitives::GroupElement> gens_g;
    std::vector <secp_primitives::GroupElement> gens_h;
    std::vector <secp_primitives::Scalar> a;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement u_;
    // generating needed objects
    generate(n, gens_g, gens_h, a, b, u_);

    secp_primitives::Scalar x;
    x.randomize();
    //    //creating proof genertor
    lelantus::InnerProductProofGenerator<secp_primitives::Scalar, secp_primitives::GroupElement> prooveGenerator(gens_g , gens_h, u_);

    //////    //generating proof
    lelantus::InnerProductProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    prooveGenerator.generate_proof(a, b, x, proof);

    ////    //create verifier
    lelantus::InnerProductProofVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(gens_g, gens_h, u_, prooveGenerator.get_P());

    BOOST_CHECK(verifier.verify(x, proof));
}

BOOST_AUTO_TEST_CASE(fake_proof_notVerify)
{
    int n = 32;
    std::vector <secp_primitives::GroupElement> gens_g;
    std::vector <secp_primitives::GroupElement> gens_h;
    std::vector <secp_primitives::Scalar> a;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement u_;
    // generating needed objects
    generate(n, gens_g, gens_h, a, b, u_);

    secp_primitives::Scalar x;
    x.randomize();
    //    //creating proof genertor
    lelantus::InnerProductProofGenerator<secp_primitives::Scalar, secp_primitives::GroupElement> prooveGenerator(gens_g, gens_h, u_);

    //////    //generating proof
    lelantus::InnerProductProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    prooveGenerator.generate_proof(a, b, x, proof);

    ////    //create verifier with fake P
    secp_primitives::GroupElement P;
    P.randomize();
    lelantus::InnerProductProofVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(gens_g, gens_h, u_, P);

    BOOST_CHECK(!verifier.verify(x, proof));
}

BOOST_AUTO_TEST_SUITE_END()