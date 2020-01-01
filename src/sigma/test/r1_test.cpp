#include "../params.h"
#include "../r1_proof.h"
#include "../r1_proof_generator.h"
#include "../r1_proof_verifier.h"

#include <boost/test/unit_test.hpp>

#include <stdlib.h>

bool test(secp_primitives::GroupElement& g, std::vector<secp_primitives::GroupElement>& h_, std::vector<secp_primitives::Scalar>& b, int n, int m){

    secp_primitives::Scalar r;
    r.randomize();
    sigma::R1ProofGenerator<secp_primitives::Scalar, secp_primitives::GroupElement> prover(g, h_, b, r, n, m);
    sigma::R1Proof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    prover.proof(proof);

    sigma::R1ProofVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(g,h_,prover.get_B(), n, m);
    return verifier.verify(proof);
}

BOOST_AUTO_TEST_SUITE(sigma_R1_test)

BOOST_AUTO_TEST_CASE(serialize_deserialize_proof)
{
    sigma::Params::get_default();
    int n = 4;
    int m = 16;
    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_;
    std::vector<secp_primitives::Scalar> b;
    secp_primitives::GroupElement h;
    for(int i = 0; i < m; ++i) {
        h.randomize();
        h_.push_back(h);
        b.push_back(secp_primitives::Scalar(unsigned(1)));
        for(int j = 1; j < n; ++j){
            h.randomize();
            h_.push_back(h);
            b.push_back(secp_primitives::Scalar(unsigned(0)));

        }
    }

    secp_primitives::Scalar r;
    r.randomize();
    sigma::R1ProofGenerator<secp_primitives::Scalar, secp_primitives::GroupElement> prover(g, h_, b, r, n, m);
    sigma::R1Proof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    prover.proof(proof);

    sigma::R1ProofVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(g,h_,prover.get_B(), n, m);
    BOOST_CHECK(verifier.verify(proof));

    unsigned char buffer [proof.memoryRequired(n, m)];
    proof.serialize(buffer);

    sigma::R1Proof<secp_primitives::Scalar, secp_primitives::GroupElement> resulted;
    resulted.deserialize(buffer,n, m);

    BOOST_CHECK(verifier.verify(resulted));
}

BOOST_AUTO_TEST_CASE(fixed_size_test)
{
    sigma::Params::get_default();
    int n = 4;
    int m = 16;
    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_;
    std::vector<secp_primitives::Scalar> b;
    secp_primitives::GroupElement h;
    for(int i = 0; i < m; ++i) {
        h.randomize();
        h_.push_back(h);
        b.push_back(secp_primitives::Scalar(unsigned(1)));
        for(int j = 1; j < n; ++j){
            h.randomize();
            h_.push_back(h);
            b.push_back(secp_primitives::Scalar(unsigned(0)));

        }
    }

    BOOST_CHECK(test(g, h_, b, n, m));
}

BOOST_AUTO_TEST_CASE(random_size_test)
{
    sigma::Params::get_default();
    int n = rand() % 64 + 16;
    int m = rand() % 32 + 16;
    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_;
    std::vector<secp_primitives::Scalar> b;
    for(int i = 0; i < m; ++i) {
        secp_primitives::GroupElement h;
        h.randomize();
        h_.push_back(h);
        b.push_back(secp_primitives::Scalar(unsigned(1)));
        for(int j = 1; j < n; ++j){
            h.randomize();
            h_.push_back(h);
            b.push_back(secp_primitives::Scalar(unsigned(0)));

        }
    }

    BOOST_CHECK(test(g, h_, b, n, m));
}


BOOST_AUTO_TEST_CASE(all_positions)
{
    sigma::Params::get_default();
    int n = 32;
    int m = 16;
    secp_primitives::GroupElement g;
    std::vector <secp_primitives::GroupElement> h_;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement h;
    for(int k = 0; k < n; ++k){
        g.randomize();
        for(int i = 0;i< m ;++i) {
            for(int j = 0;j < n;++j){
                h.randomize();
                h_.push_back(h);
                if(j == k)
                    b.push_back(secp_primitives::Scalar(unsigned(1)));
                else
                    b.push_back(secp_primitives::Scalar(unsigned(0)));
            }
        }
        BOOST_CHECK(test(g, h_, b, n, m));
        h_.clear();
        b.clear();
    }
}

BOOST_AUTO_TEST_CASE(one_in_random_position)
{
    sigma::Params::get_default();
    int n = 32;
    int m = 16;
    int k = rand() % n;
    secp_primitives::GroupElement g;
    std::vector <secp_primitives::GroupElement> h_;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement h;
    g.randomize();
    for(int i = 0;i < m;++i) {
        k = rand() % n;
        for(int j = 0;j < n;++j){
            h.randomize();
            h_.push_back(h);
            if(j == k)
                b.push_back(secp_primitives::Scalar(unsigned(1)));
            else
                b.push_back(secp_primitives::Scalar(unsigned(0)));
        }
    }
    BOOST_CHECK(test(g, h_, b, n, m));
}


BOOST_AUTO_TEST_CASE(all_0s_in_random_row)
{
    sigma::Params::get_default();
    int n = 32;
    int m = 16;
    int k = rand() % m;
    secp_primitives::GroupElement g;
    std::vector <secp_primitives::GroupElement> h_;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement h;
    g.randomize();
    for(int i = 0;i < m;++i) {
        for(int j = 0;j < n;++j){
            h.randomize();
            h_.push_back(h);
            if(i != k)
                b.push_back(secp_primitives::Scalar(unsigned(1)));
            else
                b.push_back(secp_primitives::Scalar(unsigned(0)));
        }
    }
    BOOST_CHECK(!test(g, h_, b, n, m)); // expect false
}

BOOST_AUTO_TEST_CASE(all_1s_in_random_row)
{
    sigma::Params::get_default();
    int n = 32;
    int m = 16;
    int k = rand() % m;
    secp_primitives::GroupElement g;
    std::vector <secp_primitives::GroupElement> h_;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement h;
    g.randomize();
    for(int i = 0;i < m;++i) {
        for(int j = 0;j < n;++j){
            h.randomize();
            h_.push_back(h);
            if(i == k)
                b.push_back(secp_primitives::Scalar(unsigned(1)));
            else
                b.push_back(secp_primitives::Scalar(unsigned(0)));
        }
    }
    BOOST_CHECK(!test(g, h_, b, n, m)); // expect false
}


BOOST_AUTO_TEST_CASE(two_1s_in_random_row)
{
    sigma::Params::get_default();
    int n = 32;
    int m = 16;
    int k = rand() % n;
    secp_primitives::GroupElement g;
    std::vector <secp_primitives::GroupElement> h_;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement h;
    g.randomize();
    for(int i = 0;i < m;++i) {
        for(int j = 0;j < n;++j){
            h.randomize();
            h_.push_back(h);
            if(j == k){
                b.push_back(secp_primitives::Scalar(unsigned(1)));
                b.push_back(secp_primitives::Scalar(unsigned(1)));
                h.randomize();
                h_.push_back(h);
                ++j;
            }
            else
                b.push_back(secp_primitives::Scalar(unsigned(0)));
        }
    }
    BOOST_CHECK(!test(g, h_, b, n, m)); // expect false
}

BOOST_AUTO_TEST_CASE(one_all_0s_element)
{
    sigma::Params::get_default();
    int n = 32;
    int m = 16;
    int r;
    secp_primitives::GroupElement g;
    std::vector <secp_primitives::GroupElement> h_;
    std::vector <secp_primitives::Scalar> b;
    secp_primitives::GroupElement h;
    for(int k = 0; k < n; ++k){
        g.randomize();
        r = rand() % m;
        for(int i = 0;i< m ;++i) {
            for(int j = 0;j < n;++j){
                h.randomize();
                h_.push_back(h);
                if(j == k && i != r)
                    b.push_back(secp_primitives::Scalar(unsigned(1)));
                else
                    b.push_back(secp_primitives::Scalar(unsigned(0)));
            }
        }
        BOOST_CHECK(!test(g, h_, b, n, m)); // expect false
        h_.clear();
        b.clear();
    }
}

BOOST_AUTO_TEST_SUITE_END()
