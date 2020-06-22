#include "lelantus_test_fixture.h"

#include "../../sigma/openssl_context.h"
#include "../joinsplit.h"

#include <boost/test/unit_test.hpp>
#include <openssl/rand.h>

namespace lelantus {

class JoinSplitTests : public LelantusTestingSetup
{
public:
    JoinSplitTests()
    {
    }

public:
    std::vector<PrivateCoin> GenerateCoins(std::vector<CAmount> const &amounts) {
        std::vector<PrivateCoin> privs;

        for (auto a : amounts) {
            std::vector<unsigned char> ecdsaKey;
            ecdsaKey.resize(32);

            // Create a key pair
            secp256k1_pubkey pubkey;
            do {
                if (RAND_bytes(ecdsaKey.data(), ecdsaKey.size()) != 1) {
                    throw std::runtime_error("Unable to generate randomness");
                }
            } while (!secp256k1_ec_pubkey_create(
                OpenSSLContext::get_context(), &pubkey, ecdsaKey.data()));

            // Hash the public key in the group to obtain a serial number
            auto serial = PrivateCoin::serialNumberFromSerializedPublicKey(
                OpenSSLContext::get_context(), &pubkey);

            Scalar randomness;
            randomness.randomize();

            privs.emplace_back(params, serial, a, randomness, LELANTUS_TX_VERSION_4);
            privs.back().setEcdsaSeckey(ecdsaKey);
        }

        return privs;
    }

    std::vector<PublicCoin> BuildPublicCoins(std::vector<GroupElement> const &es) {
        std::vector<PublicCoin> pubs;
        pubs.reserve(es.size());

        for (auto const &e : es) {
            pubs.emplace_back(e);
        }

        return pubs;
    }
};

BOOST_FIXTURE_TEST_SUITE(lelantus_joinsplit_tests, JoinSplitTests)

BOOST_AUTO_TEST_CASE(verify)
{
    auto privs = GenerateCoins({1 * COIN, 10 * COIN, 100 * COIN, 99 * COIN});
    std::vector<std::pair<PrivateCoin, uint32_t>> cin = {
        {privs[0], 1},
        {privs[1], 1},
        {privs[2], 2}
    };

    std::map<uint32_t, std::vector<PublicCoin>> anons = {
        {1, BuildPublicCoins(GenerateGroupElements(10))},
        {2, BuildPublicCoins(GenerateGroupElements(10))},
    };

    anons[1][0] = privs[0].getPublicCoin();
    anons[1][1] = privs[1].getPublicCoin();
    anons[2][0] = privs[2].getPublicCoin();

    // inputs = 111
    // outputs = 0.01(fee) + 99(mint) + 11.99(vout)
    auto vout = 12 * COIN - CENT;
    JoinSplit joinSplit(
        params,
        cin,
        anons,
        vout, // vout
        {privs[3]}, // cout
        CENT, // fee
        {ArithToUint256(1), ArithToUint256(2)},
        ArithToUint256(3));

    std::vector<uint32_t> expectedGroupIds = {1, 1, 2};
    BOOST_CHECK(expectedGroupIds == joinSplit.getCoinGroupIds());
    BOOST_CHECK(joinSplit.Verify(anons, {privs[3].getPublicCoin()}, vout, ArithToUint256(3)));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus