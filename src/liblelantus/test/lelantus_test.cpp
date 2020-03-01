#include "../lelantus_prover.h"
#include "../lelantus_verifier.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(lelantus_protocol_tests)

BOOST_AUTO_TEST_CASE(prove_verify)
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
    for(int i = 1; i < N; ++i){
          secp_primitives::GroupElement coin;
          coin.randomize();
          anonymity_set.push_back(lelantus::PublicCoin(coin, uint64_t(15)));
     }

    secp_primitives::Scalar Vin(uint64_t(5));
    secp_primitives::Scalar Vout(uint64_t(6));
    std::vector <lelantus::PrivateCoin> Cout;
    Cout.push_back(lelantus::PrivateCoin(params, secp_primitives::Scalar(uint64_t(2))));
    Cout.push_back(lelantus::PrivateCoin(params, secp_primitives::Scalar(uint64_t(1))));
    secp_primitives::Scalar f(uint64_t(1));

    lelantus::LelantusProof proof;

    lelantus::LelantusProver prover(params);
    prover.proof(anonymity_set, Vin, Cin, indexes, Vout, Cout, f,  proof);

    std::vector<secp_primitives::Scalar> Sin;
    for(int i = 0; i < Cin.size(); ++i)
        Sin.push_back(Cin[i].getSerialNumber());

    std::vector<lelantus::PublicCoin> Cout_Public;
    for(int i = 0; i < Cout.size(); ++i)
        Cout_Public.push_back(Cout[i].getPublicCoin());
    lelantus::LelantusVerifier verifier(params);
    BOOST_CHECK(verifier.verify(anonymity_set, Sin, Vin, Vout, f, Cout_Public, proof));
}

BOOST_AUTO_TEST_SUITE_END()