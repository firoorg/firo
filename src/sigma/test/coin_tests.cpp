#include "../coin.h"
#include "../params.h"

#include "../../streams.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(sigma_coin_tests)

BOOST_AUTO_TEST_CASE(pubcoin_serialization)
{
    secp_primitives::GroupElement coin;
    coin.randomize();

    sigma::PublicCoin pubcoin(coin, sigma::CoinDenomination::SIGMA_DENOM_10);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << pubcoin;

    sigma::PublicCoin deserialized;
    serialized >> deserialized;

    BOOST_CHECK(pubcoin == deserialized);
}

BOOST_AUTO_TEST_CASE(pubcoin_validate)
{
    auto params = sigma::Params::get_default();

    sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    auto& pubcoin = privcoin.getPublicCoin();

    BOOST_CHECK(pubcoin.validate());
}

BOOST_AUTO_TEST_CASE(getter_setter_priv)
{
    auto params = sigma::Params::get_default();

    sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PrivateCoin new_privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);

    BOOST_CHECK(privcoin.getPublicCoin() != new_privcoin.getPublicCoin());
    BOOST_CHECK(privcoin.getSerialNumber() != new_privcoin.getSerialNumber());
    BOOST_CHECK(privcoin.getRandomness() != new_privcoin.getRandomness());
    BOOST_CHECK(privcoin.getVersion() == new_privcoin.getVersion());

    new_privcoin.setPublicCoin(privcoin.getPublicCoin());
    new_privcoin.setRandomness(privcoin.getRandomness());
    new_privcoin.setSerialNumber(privcoin.getSerialNumber());
    new_privcoin.setVersion(2);

    BOOST_CHECK(privcoin.getPublicCoin() == new_privcoin.getPublicCoin());
    BOOST_CHECK(privcoin.getSerialNumber() == new_privcoin.getSerialNumber());
    BOOST_CHECK(privcoin.getRandomness() == new_privcoin.getRandomness());
    BOOST_CHECK(new_privcoin.getVersion() == 2);
}

BOOST_AUTO_TEST_SUITE_END()
