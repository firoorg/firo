#include "lelantus_test_fixture.h"

#include "../lelantus_prover.h"
#include "../lelantus_verifier.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

class ProtocolTests : public LelantusTestingSetup
{
public:
    ProtocolTests()
        : params(Params::get_default())
    {
    }

public:
    std::vector<PublicCoin> ExtractPublicCoins(std::vector<PrivateCoin> const &coins) const {
        std::vector<PublicCoin> pubs;
        pubs.reserve(coins.size());

        for (auto const &c : coins) {
            pubs.push_back(c.getPublicCoin());
        }

        return pubs;
    }

    std::vector<Scalar> ExtractSerials(
        size_t anonymitySets,
        std::vector<std::pair<PrivateCoin, uint32_t>> const &Cin,
        std::vector<uint32_t>& groupIds) const {
        std::vector<Scalar> serials;
        for (auto const &in : Cin) {
            serials.push_back(in.first.getSerialNumber());
            groupIds.push_back(in.second);
        }

        return serials;
    }

    std::map<uint32_t, std::vector<PublicCoin>> GenerateAnonymitySets(std::initializer_list<size_t> sizes) const {
        std::map<uint32_t, std::vector<PublicCoin>> sets;

        uint32_t id = 0;
        for (size_t s : sizes) {
            std::vector<PublicCoin> set;
            GenerateGroupElements(s, std::back_inserter(set));
            sets[id] = set;
            id++;
        }

        return sets;
    }

public:
    Params const *params;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_protocol_tests, ProtocolTests)

BOOST_AUTO_TEST_CASE(prove_verify)
{
    size_t N = 100;

    uint64_t v1(5);
    PrivateCoin input_coin1(params ,v1);
    std::vector<std::pair<PrivateCoin, uint32_t>> Cin = {{input_coin1, 0}};

    std::vector <size_t> indexes = {0};

    auto anonymity_sets = GenerateAnonymitySets({N});
    anonymity_sets[0][0] = Cin[0].first.getPublicCoin();

    Scalar Vin(5);
    uint64_t Vout(6);
    std::vector<PrivateCoin> Cout = {{params, 2}, {params, 1}};

    uint64_t f(1);
    LelantusProof proof;

    LelantusProver prover(params);
    prover.proof(anonymity_sets, Vin, Cin, indexes, Vout, Cout, f,  proof);

    std::vector<uint32_t> groupIds;
    auto Sin = ExtractSerials(anonymity_sets.size(), Cin, groupIds);
    auto Cout_Public = ExtractPublicCoins(Cout);

    lelantus::LelantusVerifier verifier(params);
    BOOST_CHECK(verifier.verify(anonymity_sets, Sin, groupIds, Vin, Vout, f, Cout_Public, proof));
}

BOOST_AUTO_TEST_CASE(prove_verify_many_coins)
{
    size_t N = 100;

    PrivateCoin input1(params ,2), input2(params, 2), input3(params, 1);
    std::vector<std::pair<PrivateCoin, uint32_t>> Cin = {
        {input1, 0}, {input2, 0}, {input3, 1}
    };

    std::vector <size_t> indexes = {0, 1, 0};

    auto anonymity_sets = GenerateAnonymitySets({N, N});
    anonymity_sets[0][0] = Cin[0].first.getPublicCoin();
    anonymity_sets[0][1] = Cin[1].first.getPublicCoin();
    anonymity_sets[1][0] = Cin[2].first.getPublicCoin();

    Scalar Vin(5);
    uint64_t Vout(6), f(1);
    std::vector<PrivateCoin> Cout = {{params, 2}, {params, 1}};

    LelantusProof proof;

    LelantusProver prover(params);
    prover.proof(anonymity_sets, Vin, Cin, indexes, Vout, Cout, f,  proof);

    std::vector<uint32_t> groupIds;
    auto Sin = ExtractSerials(anonymity_sets.size(), Cin, groupIds);
    auto Cout_Public = ExtractPublicCoins(Cout);

    lelantus::LelantusVerifier verifier(params);
    BOOST_CHECK(verifier.verify(anonymity_sets, Sin, groupIds, Vin, Vout, f, Cout_Public, proof));
    BOOST_CHECK(verifier.verify(anonymity_sets, Sin, groupIds, Vin + 1, Vout + 1, f, Cout_Public, proof));
    BOOST_CHECK(verifier.verify(anonymity_sets, Sin, groupIds, Vin, Vout + f, uint64_t(0), Cout_Public, proof));
}

BOOST_AUTO_TEST_CASE(imbalance_proof_should_fail)
{
    size_t N = 100;

    // Input
    PrivateCoin p1(params, 3);
    std::vector<std::pair<PrivateCoin, uint32_t>> Cin = {{p1, 0}};

    std::vector<size_t> indexs = {0};

    auto anonymitySets = GenerateAnonymitySets({N});
    anonymitySets[0][0] = Cin[0].first.getPublicCoin();

    Scalar Vin(2); // Use this to verify
    Scalar FakeVin(4); // Use this to generate proof

    // Output
    std::vector<PrivateCoin> Cout = {{params, 3}};
    uint64_t Vout(3);
    uint64_t f(1);

    // Proof
    LelantusProof proof;

    // Should be prevent from prover
    LelantusProver prover(params);
    BOOST_CHECK_THROW(prover.proof(anonymitySets, Vin, Cin, indexs, Vout, Cout, f, proof), ZerocoinException);

    // Use fake vin
    prover.proof(anonymitySets, FakeVin, Cin, indexs, Vout, Cout, f, proof);

    // Verify
    std::vector<uint32_t> groupIds;
    auto Sin = ExtractSerials(anonymitySets.size(), Cin, groupIds);
    auto publicCoins = ExtractPublicCoins(Cout);

    LelantusVerifier verifier(params);

    // input: 2 + 3(anonymous), output: 3 + 3(anonymous) + 1(fee)
    BOOST_CHECK(!verifier.verify(anonymitySets, Sin, groupIds, Vin, Vout, f, publicCoins, proof));

    // Verify with output which is less than input also should fail
    // input: 99 + 3(anonymous), output: 3 + 3(anonymous) + 1(fee)
    Scalar newVin(99);
    BOOST_CHECK(!verifier.verify(anonymitySets, Sin, groupIds, newVin, Vout, f, publicCoins, proof));
}

BOOST_AUTO_TEST_CASE(other_fail_to_validate)
{
    size_t N = 100;

    // Input
    PrivateCoin p1(params, 1), p2(params, 2);
    std::vector<std::pair<PrivateCoin, uint32_t>> Cin = {{p1, 0}, {p2, 0}};

    std::vector<size_t> indexs = {0, 1};

    auto anonymitySets = GenerateAnonymitySets({N});
    anonymitySets[0][0] = Cin[0].first.getPublicCoin();
    anonymitySets[0][1] = Cin[1].first.getPublicCoin();

    Scalar Vin(4);

    // Output
    std::vector<PrivateCoin> Cout = {{params, 1}, {params, 2}};
    uint64_t Vout(3);
    uint64_t f(1);

    // Proof
    LelantusProof proof;

    // Should be prevent from prover
    LelantusProver prover(params);
    prover.proof(anonymitySets, Vin, Cin, indexs, Vout, Cout, f, proof);

    // Verify
    std::vector<uint32_t> groupIds;
    auto Sin = ExtractSerials(anonymitySets.size(), Cin, groupIds);
    auto publicCoins = ExtractPublicCoins(Cout);

    LelantusVerifier verifier(params);

    BOOST_CHECK(verifier.verify(anonymitySets, Sin, groupIds, Vin, Vout, f, publicCoins, proof));

    // Invalid group
    auto invalidAnonymitySets = anonymitySets;
    invalidAnonymitySets[0].pop_back();
    BOOST_CHECK(!verifier.verify(invalidAnonymitySets, Sin, groupIds, Vin, Vout, f, publicCoins, proof));

    invalidAnonymitySets = anonymitySets;
    invalidAnonymitySets[0].push_back(PrivateCoin(params, 1).getPublicCoin());
    BOOST_CHECK(!verifier.verify(invalidAnonymitySets, Sin, groupIds, Vin, Vout, f, publicCoins, proof));

    // Invalid serial
    auto invalidSin = Sin;
    invalidSin[1].randomize();
    BOOST_CHECK(!verifier.verify(anonymitySets, invalidSin, groupIds, Vin, Vout, f, publicCoins, proof));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus