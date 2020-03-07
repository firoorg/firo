#include "../lelantus_prover.h"
#include "../lelantus_verifier.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(lelantus_serialize_tests)

BOOST_AUTO_TEST_CASE(serialize)
{
    auto params = lelantus::Params::get_default();
    std::vector <lelantus::PublicCoin> anonymity_set;
    int N = 100;

    std::vector <lelantus::PrivateCoin> Cin;
    secp_primitives::Scalar v1(uint64_t(5));
    lelantus::PrivateCoin input_coin1(params ,v1);
    Cin.push_back(input_coin1);
    std::vector <uint64_t> indexes;
    indexes.push_back(0);
    anonymity_set.reserve(N);
    anonymity_set.push_back(Cin[0].getPublicCoin());
    for(int i = 0; i < N; ++i){
          secp_primitives::GroupElement coin;
          coin.randomize();
          anonymity_set.push_back(lelantus::PublicCoin(coin));
     }

    secp_primitives::Scalar Vin(uint64_t(5));
    secp_primitives::Scalar Vout(uint64_t(6));
    std::vector <lelantus::PrivateCoin> Cout;
    Cout.push_back(lelantus::PrivateCoin(params, secp_primitives::Scalar(uint64_t(2))));
    Cout.push_back(lelantus::PrivateCoin(params, secp_primitives::Scalar(uint64_t(1))));
    secp_primitives::Scalar f(uint64_t(1));

    lelantus::LelantusProof initial_proof;

    lelantus::LelantusProver prover(params);
    prover.proof(anonymity_set, Vin, Cin, indexes, Vout, Cout, f,  initial_proof);

    unsigned char buffer [initial_proof.memoryRequired(1, params->get_bulletproofs_n(), 2)];
    initial_proof.serialize(buffer);

    lelantus::LelantusProof resulted_proof;
    resulted_proof.deserialize(params, buffer, 1, 2);

    for(int i = 0; i <  initial_proof.sigma_proofs.size(); ++i){
        BOOST_CHECK(initial_proof.sigma_proofs[i].B_ == resulted_proof.sigma_proofs[i].B_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].A_ == resulted_proof.sigma_proofs[i].A_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].C_ == resulted_proof.sigma_proofs[i].C_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].D_ == resulted_proof.sigma_proofs[i].D_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].f_ == resulted_proof.sigma_proofs[i].f_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].ZA_ == resulted_proof.sigma_proofs[i].ZA_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].ZC_ == resulted_proof.sigma_proofs[i].ZC_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].Gk_ == resulted_proof.sigma_proofs[i].Gk_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].zV_ == resulted_proof.sigma_proofs[i].zV_);
        BOOST_CHECK(initial_proof.sigma_proofs[i].zR_ == resulted_proof.sigma_proofs[i].zR_);
    }

    BOOST_CHECK(initial_proof.bulletproofs.A == resulted_proof.bulletproofs.A);
    BOOST_CHECK(initial_proof.bulletproofs.S == resulted_proof.bulletproofs.S);
    BOOST_CHECK(initial_proof.bulletproofs.T1 == resulted_proof.bulletproofs.T1);
    BOOST_CHECK(initial_proof.bulletproofs.T2 == resulted_proof.bulletproofs.T2);
    BOOST_CHECK(initial_proof.bulletproofs.T_x1 == resulted_proof.bulletproofs.T_x1);
    BOOST_CHECK(initial_proof.bulletproofs.T_x2 == resulted_proof.bulletproofs.T_x2);
    BOOST_CHECK(initial_proof.bulletproofs.u == resulted_proof.bulletproofs.u);
    BOOST_CHECK(initial_proof.bulletproofs.innerProductProof.a_ == resulted_proof.bulletproofs.innerProductProof.a_);
    BOOST_CHECK(initial_proof.bulletproofs.innerProductProof.b_ == resulted_proof.bulletproofs.innerProductProof.b_);
    BOOST_CHECK(initial_proof.bulletproofs.innerProductProof.c_ == resulted_proof.bulletproofs.innerProductProof.c_);
    BOOST_CHECK(initial_proof.bulletproofs.innerProductProof.L_ == resulted_proof.bulletproofs.innerProductProof.L_);
    BOOST_CHECK(initial_proof.bulletproofs.innerProductProof.R_ == resulted_proof.bulletproofs.innerProductProof.R_);

        BOOST_CHECK(initial_proof.schnorrProof.u == resulted_proof.schnorrProof.u);
        BOOST_CHECK(initial_proof.schnorrProof.P1 == resulted_proof.schnorrProof.P1);
        BOOST_CHECK(initial_proof.schnorrProof.T1 == resulted_proof.schnorrProof.T1);
}

BOOST_AUTO_TEST_SUITE_END()
