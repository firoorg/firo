#include "../params.h"
#include "../sigmaplus_prover.h"
#include "../sigmaplus_verifier.h"

#include <boost/test/unit_test.hpp>

#include "../../test/fixtures.h"

BOOST_FIXTURE_TEST_SUITE(sigma_serialize_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(group_element_serialize)
{
    secp_primitives::GroupElement initial;
    initial.randomize();
    unsigned char buffer [initial.memoryRequired()];
    initial.serialize(buffer);
    secp_primitives::GroupElement resulted;
    resulted.deserialize(buffer);
    BOOST_CHECK(initial == resulted);
}

BOOST_AUTO_TEST_CASE(group_element_invalid)
{
    // Invalid GroupElement generated in advance
    std::string str = " F I R O   T E S T   S T R I N G ";
    std::vector<unsigned char> buffer(str.begin(), str.end());
    buffer.push_back(0);
    secp_primitives::GroupElement resulted;
    BOOST_CHECK_THROW(resulted.deserialize(buffer.data()), std::exception);

}

BOOST_AUTO_TEST_CASE(group_element_serialize_infinity)
{
    secp_primitives::GroupElement initial;
    unsigned char buffer [initial.memoryRequired()];
    initial.serialize(buffer);
    secp_primitives::GroupElement resulted;
    BOOST_CHECK_NO_THROW(resulted.deserialize(buffer));
    BOOST_CHECK(resulted.isInfinity());
    BOOST_CHECK(initial == resulted);
}

BOOST_AUTO_TEST_CASE(scalar_serialize)
{
    secp_primitives::Scalar initial;
    initial.randomize();
    unsigned char buffer [initial.memoryRequired()];
    initial.serialize(buffer);
    secp_primitives::Scalar resulted;
    resulted.deserialize(buffer);
    BOOST_CHECK(initial == resulted);
}

BOOST_AUTO_TEST_CASE(proof_serialize)
{
    auto params = sigma::Params::get_default();
    int N = 16384;
    int n = params->get_n();
    int m = params->get_m();
    int index = 0;

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

    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> initial_proof(n, m);

    prover.proof(commits, index, r, true, initial_proof);

    auto size = initial_proof.memoryRequired();
    std::vector<unsigned char> buffer(size);
    initial_proof.serialize(buffer.data());
    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> resulted_proof(n, m);
    resulted_proof.deserialize(buffer.data());

    BOOST_CHECK(initial_proof.B_ == resulted_proof.B_);
    BOOST_CHECK(initial_proof.r1Proof_.A_ == resulted_proof.r1Proof_.A_);
    BOOST_CHECK(initial_proof.r1Proof_.C_ == resulted_proof.r1Proof_.C_);
    BOOST_CHECK(initial_proof.r1Proof_.D_ == resulted_proof.r1Proof_.D_);
    BOOST_CHECK(initial_proof.r1Proof_.f_ == resulted_proof.r1Proof_.f_);
    BOOST_CHECK(initial_proof.r1Proof_.ZA_ == resulted_proof.r1Proof_.ZA_);
    BOOST_CHECK(initial_proof.r1Proof_.ZC_ == resulted_proof.r1Proof_.ZC_);
    BOOST_CHECK(initial_proof.Gk_ == resulted_proof.Gk_);
    BOOST_CHECK(initial_proof.z_ == resulted_proof.z_);
}

BOOST_AUTO_TEST_SUITE_END()
