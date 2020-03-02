#include "../coin.h"
#include "../coinspend.h"
#include "../spend_metadata.h"

#include "../../streams.h"
#include "../../uint256.h"

#include "../../test/fixtures.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sigma_coin_spend_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(serialize_deserialize_test)
{
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData, true);

    // serialize
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << coin;

    // deserialize
    sigma::CoinSpend new_coin(params, serialized);

    BOOST_CHECK(coin.getAccumulatorBlockHash().Compare(new_coin.getAccumulatorBlockHash())==0);
    BOOST_CHECK(coin.getCoinSerialNumber() == new_coin.getCoinSerialNumber());
    BOOST_CHECK(coin.getDenomination() == new_coin.getDenomination());
    BOOST_CHECK(coin.getVersion() == new_coin.getVersion());
}

BOOST_AUTO_TEST_CASE(different_anonymity_set)
{
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params,privcoin,anonymity_set, metaData, true);
    sigma::CoinSpend coin2(params,privcoin,anonymity_set, metaData, true);

    BOOST_CHECK(coin.getCoinSerialNumber() == coin2.getCoinSerialNumber());

    // use different anonymity_set
    const sigma::PrivateCoin privcoin3(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin3;
    pubcoin3 = privcoin3.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set3;
    anonymity_set3.push_back(pubcoin);
    anonymity_set3.push_back(pubcoin3);

    sigma::CoinSpend coin3(params, privcoin, anonymity_set3, metaData, true);

    BOOST_CHECK(coin.getCoinSerialNumber() == coin3.getCoinSerialNumber());
}

BOOST_AUTO_TEST_CASE(out_of_anonymity_set)
{
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);

    // use different anonymity_set
    const sigma::PrivateCoin privcoin3(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin3;
    pubcoin3 = privcoin3.getPublicCoin();

    // [pubcoin3]
    std::vector<sigma::PublicCoin> anonymity_set3;
    anonymity_set3.push_back(pubcoin3);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    // pubcoin of privcoin isn't in [pubcoin3]
    BOOST_CHECK_THROW(sigma::CoinSpend(params, privcoin, anonymity_set3, metaData, true),std::exception);
}

BOOST_AUTO_TEST_CASE(verify_test)
{
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend spend_coin(params, privcoin, anonymity_set, metaData, true);

    BOOST_CHECK(spend_coin.Verify(anonymity_set, metaData, true));
}

BOOST_AUTO_TEST_CASE(verify_test_valid_set_plus_one)
{
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    const sigma::PrivateCoin privcoin2(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin2;
    pubcoin2 = privcoin2.getPublicCoin();

    // [pubcoin]
    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend spend_coin(params,privcoin,anonymity_set, metaData, true);

    // [pubcoin,pubcoin2]
    std::vector<sigma::PublicCoin> anonymity_set2;
    anonymity_set2.push_back(pubcoin);
    anonymity_set2.push_back(pubcoin2);

    BOOST_CHECK(!spend_coin.Verify(anonymity_set2, metaData, true));
}

BOOST_AUTO_TEST_CASE(verify_test_valid_set_subtract_one)
{
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    const sigma::PrivateCoin privcoin2(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin2;
    pubcoin2 = privcoin2.getPublicCoin();

    // [pubcoin,pubcoin2]
    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);
    anonymity_set.push_back(pubcoin2);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend spend_coin(params, privcoin, anonymity_set, metaData, true);

    // [pubcoin]
    std::vector<sigma::PublicCoin> anonymity_set2;
    anonymity_set2.push_back(pubcoin);

    BOOST_CHECK(!spend_coin.Verify(anonymity_set2, metaData, true));
}

BOOST_AUTO_TEST_CASE(verify_test_with_accumulatorBlockHash)
{
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));
    sigma::CoinSpend spend_coin(params, privcoin, anonymity_set, metaData, true);

    BOOST_CHECK(spend_coin.Verify(anonymity_set, metaData, true));
}

BOOST_AUTO_TEST_SUITE_END()
