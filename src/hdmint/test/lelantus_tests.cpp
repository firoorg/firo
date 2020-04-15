#include "../../test/fixtures.h"
#include "../wallet.h"

#include <boost/test/unit_test.hpp>

class HDMintLelantusTests : public ZerocoinTestingSetup200
{
public:
    HDMintLelantusTests() :
        params(lelantus::Params::get_default()) {
    }

public:
    MintPoolEntry FrontMintPool() const {
        LOCK(pwalletMain->cs_wallet);

        auto nCountNextUse = zwalletMain->GetCount();
        auto mints = CWalletDB(pwalletMain->strWalletFile).ListMintPool();

        for (auto &m : mints) {
            if (std::get<2>(m.second) == nCountNextUse) {
                return m.second;
            }
        }

        throw std::runtime_error("next count is not available");
    }

public:
    lelantus::Params const *params;
};

BOOST_FIXTURE_TEST_SUITE(hdmint_lelantus_tests, HDMintLelantusTests)

BOOST_AUTO_TEST_CASE(deterministic_coin_generation_from_seed)
{
    std::array<unsigned char, 64> rawSeed1, rawSeed2;
    std::fill(rawSeed1.begin(), rawSeed1.end(), 0);
    std::fill(rawSeed2.begin(), rawSeed2.end(), 0);
    rawSeed2.back() = 1;

    uint512 seed1(rawSeed1), seed2(rawSeed2);

    lelantus::PrivateCoin
        coin1(params, 1),
        coin2(params, 1),
        coin3(params, 1);

    BOOST_CHECK(zwalletMain->SeedToLelantusMint(seed1, coin1));
    BOOST_CHECK(zwalletMain->SeedToLelantusMint(seed2, coin2));
    BOOST_CHECK(zwalletMain->SeedToLelantusMint(seed1, coin3));

    // TODO: compare private coin directly instead of comparing via mint
    auto pubCoin1 = coin1.getPublicCoin();
    auto pubCoin2 = coin2.getPublicCoin();
    auto pubCoin3 = coin3.getPublicCoin();

    BOOST_CHECK(pubCoin1 == pubCoin3);
    BOOST_CHECK(pubCoin1 != pubCoin2);
}

BOOST_AUTO_TEST_CASE(lelantus_mint_generation)
{
    lelantus::PrivateCoin
        coin1(params, 1),
        coin2(params, 1);

    CHDMint mint1, mint2;

    // coin should be valid
    BOOST_CHECK(zwalletMain->GenerateLelantusMint(coin1, mint1));
    BOOST_CHECK(zwalletMain->GenerateLelantusMint(coin2, mint2));

    auto entry = FrontMintPool();

    BOOST_CHECK_EQUAL(2, std::get<2>(entry));

    auto pubCoin1 = coin1.getPublicCoin();
    auto pubCoin2 = coin2.getPublicCoin();

    // verify
    BOOST_CHECK(pubCoin1 != pubCoin2);
    BOOST_CHECK_EQUAL(0, mint1.GetCount());
    BOOST_CHECK_EQUAL(1, mint2.GetCount());

    // chain state
    BOOST_CHECK_EQUAL(-1, mint1.GetHeight());
    BOOST_CHECK_EQUAL(-1, mint1.GetId());
    BOOST_CHECK(mint1.GetTxHash().IsNull());
    BOOST_CHECK(!mint1.IsUsed());

    // value should be unique
    BOOST_CHECK(mint1.GetSeedId() != mint2.GetSeedId());
    BOOST_CHECK(mint1.GetSerialHash() != mint2.GetSerialHash());
    BOOST_CHECK(mint1.GetPubcoinValue() != mint2.GetPubcoinValue());
    BOOST_CHECK(mint1.GetPubCoinHash() != mint2.GetPubCoinHash());
}

BOOST_AUTO_TEST_CASE(lelantus_mint_regeneration)
{
    lelantus::PrivateCoin
        coin1(params, 1),
        coin2(params, 1);

    CHDMint mint1, mint2;
    auto entry1 = FrontMintPool();

    BOOST_CHECK(zwalletMain->GenerateLelantusMint(coin1, mint1));

    // re-generate
    BOOST_CHECK(zwalletMain->GenerateLelantusMint(coin2, mint2, entry1));

    auto pubCoin1 = coin1.getPublicCoin();
    auto pubCoin2 = coin2.getPublicCoin();

    // verify
    BOOST_CHECK(pubCoin1 == pubCoin2);
    BOOST_CHECK_EQUAL(0, mint1.GetCount());
    BOOST_CHECK_EQUAL(0, mint2.GetCount());

    // chain state
    BOOST_CHECK_EQUAL(-1, mint2.GetHeight());
    BOOST_CHECK_EQUAL(-1, mint2.GetId());
    BOOST_CHECK(mint2.GetTxHash().IsNull());
    BOOST_CHECK(!mint2.IsUsed());

    // value should be the same
    BOOST_CHECK(mint1.GetSeedId() == mint2.GetSeedId());
    BOOST_CHECK(mint1.GetSerialHash() == mint2.GetSerialHash());
    BOOST_CHECK(mint1.GetPubcoinValue() == mint2.GetPubcoinValue());
    BOOST_CHECK(mint1.GetPubCoinHash() == mint2.GetPubCoinHash());
}

BOOST_AUTO_TEST_SUITE_END()