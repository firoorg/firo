#include "../Coin.h"
#include "../Params.h"
#include "../../../streams.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(sigma_coin_tests)

BOOST_AUTO_TEST_CASE(pubcoin_serialization)
{
    secp_primitives::GroupElement coin;
    coin.randomize();

    sigma::PublicCoinV3 pubcoin(coin, sigma::ZQ_GOLDWASSER);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << pubcoin;

    sigma::PublicCoinV3 deserialized;
    serialized >> deserialized;

    BOOST_CHECK(pubcoin == deserialized);
}

BOOST_AUTO_TEST_CASE(pubcoin_validate)
{
    auto params = sigma::ParamsV3::get_default();

    sigma::PrivateCoinV3 privcoin(params);
    auto& pubcoin = privcoin.getPublicCoin();

    BOOST_CHECK(pubcoin.validate());
}

BOOST_AUTO_TEST_SUITE_END()
