#include <gtest/gtest.h>
#include <nextgen/RangeProver.h>
#include <nextgen/RangeVerifier.h>

//TEST(RangeProofTests, Proof_verify)
//{
//    uint64_t n = 64;
//    secp_primitives::GroupElement g_gen, h_gen;
//    g_gen.randomize();
//    h_gen.randomize();
//    //creating generators g, h vectors
//    std::vector <secp_primitives::GroupElement> g_;
//    std::vector <secp_primitives::GroupElement> h_;
//    for (int i = 0; i < n; ++i) {
//        secp_primitives::GroupElement g;
//        secp_primitives::GroupElement h;
//        g.randomize();
//        g_.push_back(g);
//        h.randomize();
//        h_.push_back(h);
//    }
//
//    nextgen::RangeProver<secp_primitives::Scalar, secp_primitives::GroupElement> rangeProver(g_gen, h_gen, g_, h_, n);
//    nextgen::RangeProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
//    secp_primitives::Scalar v(uint64_t(70001)), r;
//    r.randomize();
//    rangeProver.proof(v, r, proof);
//    secp_primitives::GroupElement V = g_gen * v +  h_gen * r;
//    nextgen::RangeVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> rangeVerifier(g_gen, h_gen, g_, h_, n);
//    EXPECT_TRUE(rangeVerifier.verify(V, proof));
//    EXPECT_TRUE(rangeVerifier.verify_fast(V, proof));
//    EXPECT_TRUE(rangeVerifier.verify_optimised(V, proof));
//}
//
//TEST(RangeProofTests, Proof_notVerify_out_of_range)
//{
//    uint64_t n = 16;
//    secp_primitives::GroupElement g_gen, h_gen;
//    g_gen.randomize();
//    h_gen.randomize();
//    //creating generators g, h
//    std::vector <secp_primitives::GroupElement> g_;
//    std::vector <secp_primitives::GroupElement> h_;
//    for (int i = 0; i < n; ++i) {
//        secp_primitives::GroupElement g;
//        secp_primitives::GroupElement h;
//        g.randomize();
//        g_.push_back(g);
//        h.randomize();
//        h_.push_back(h);
//    }
//
//    nextgen::RangeProver<secp_primitives::Scalar, secp_primitives::GroupElement> rangeProver(g_gen, h_gen, g_, h_, n);
//    nextgen::RangeProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
//    secp_primitives::Scalar v(uint64_t(70001)), r;
//    r.randomize();
//    rangeProver.proof(v, r, proof);
//    secp_primitives::GroupElement V = g_gen * v +  h_gen * r;
//    nextgen::RangeVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> rangeVerifier(g_gen, h_gen, g_, h_, n);
//    EXPECT_FALSE(rangeVerifier.verify(V, proof));
//    EXPECT_FALSE(rangeVerifier.verify_fast(V, proof));
//    EXPECT_FALSE(rangeVerifier.verify_optimised(V, proof));
//
//}
//
//TEST(RangeProofTests, fake_Proof_notVerify)
//{
//    uint64_t n = 16;
//    secp_primitives::GroupElement g_gen, h_gen;
//    g_gen.randomize();
//    h_gen.randomize();
//    //creating generators g, h
//    std::vector <secp_primitives::GroupElement> g_;
//    std::vector <secp_primitives::GroupElement> h_;
//    for (int i = 0; i < n; ++i) {
//        secp_primitives::GroupElement g;
//        secp_primitives::GroupElement h;
//        g.randomize();
//        g_.push_back(g);
//        h.randomize();
//        h_.push_back(h);
//    }
//
//    nextgen::RangeProver<secp_primitives::Scalar, secp_primitives::GroupElement> rangeProver(g_gen, h_gen, g_, h_, n);
//    nextgen::RangeProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
//    secp_primitives::Scalar v(uint64_t(71)), r;
//    r.randomize();
//    rangeProver.proof(v, r, proof);
//    secp_primitives::GroupElement V = g_gen * v +  h_gen * r;
//    nextgen::RangeVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> rangeVerifier(g_gen, h_gen, g_, h_, n);
//
//    secp_primitives::GroupElement V_fake;
//    V_fake.randomize();
//    EXPECT_FALSE(rangeVerifier.verify(V_fake, proof));
//    EXPECT_FALSE(rangeVerifier.verify_fast(V_fake, proof));
//    EXPECT_FALSE(rangeVerifier.verify_optimised(V_fake, proof));
//
//}

TEST(RangeProofTests, Proof_verify_batch)
{
    uint64_t n = 64;
    uint64_t m = 2;
    secp_primitives::GroupElement g_gen, h_gen;
    g_gen.randomize();
    h_gen.randomize();
    //creating generators g, h vectors
    std::vector <secp_primitives::GroupElement> g_;
    std::vector <secp_primitives::GroupElement> h_;
    for (int i = 0; i < n * m; ++i) {
        secp_primitives::GroupElement g;
        secp_primitives::GroupElement h;
        g.randomize();
        g_.push_back(g);
        h.randomize();
        h_.push_back(h);
    }

    std::vector<secp_primitives::Scalar> v_s, r_s;
    std::vector<secp_primitives::GroupElement> V;
    for(int j = 0; j < m; ++j){
        secp_primitives::Scalar v(uint64_t(701+j)), r;
        r.randomize();
        v_s.push_back(v);
        r_s.push_back(r);
        V.push_back(g_gen * v +  h_gen * r);
    }

    nextgen::RangeProver<secp_primitives::Scalar, secp_primitives::GroupElement> rangeProver(g_gen, h_gen, g_, h_, n);
    nextgen::RangeProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    rangeProver.batch_proof(v_s, r_s, proof);

    nextgen::RangeVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> rangeVerifier(g_gen, h_gen, g_, h_, n);
    EXPECT_TRUE(rangeVerifier.verify_batch(V, proof));
}