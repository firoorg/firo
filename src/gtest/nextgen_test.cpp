#include <gtest/gtest.h>
#include <nextgen/NextGenProver.h>
#include <nextgen/NextGenVerifier.h>
using namespace nextgen;
using namespace secp_primitives;
TEST(nextgen_test, proof_verify)
{
    Params* params = Params::get_default();
    std::vector <PublicCoin> anonymity_set;
    int N = 1;

    std::vector <PrivateCoin> Cin;
    Scalar v1(uint64_t(1));
    PrivateCoin input_coin1(params ,v1);
    Cin.push_back(input_coin1);
    std::vector <uint64_t> indexes;
    indexes.push_back(0);
    anonymity_set.reserve(N);
    anonymity_set.push_back(Cin[0].getPublicCoin());
    for(int i = 0; i < N; ++i){
          GroupElement coin;
          coin.randomize();
          anonymity_set.push_back(PublicCoin(coin, uint64_t(15)));
     }

    Scalar Vin(uint64_t(5));
    Scalar Vout(uint64_t(5));
    std::vector <PrivateCoin> Cout;
//    Cout.push_back(PrivateCoin(params ,Scalar(uint64_t(2))));
//    Cout.push_back(PrivateCoin(params ,Scalar(uint64_t(1))));
//    Cout.push_back(PrivateCoin(params ,Scalar(uint64_t(1))));
    Scalar f(uint64_t(1));

    NextGenProof proof;

    NextGenProver prover(params);
    prover.proof(anonymity_set, Vin, Cin, indexes, Vout, Cout, f,  proof);

    std::vector<Scalar> Sin;
    for(int i = 0; i < Cin.size(); ++i)
        Sin.push_back(Cin[i].getSerialNumber());

    std::vector<PublicCoin> Cout_Public;
    for(int i = 0; i < Cout.size(); ++i)
        Cout_Public.push_back(Cout[i].getPublicCoin());
    NextGenVerifier verifier(params);
    EXPECT_TRUE(verifier.verify(anonymity_set, Sin, Vin, Vout, f, Cout_Public, proof));
}