#include <gtest/gtest.h>
#include <libzerocoin/sigma/Coin.h>
#include <libzerocoin/sigma/Params.h>
#include "../streams.h"

using namespace sigma;
using namespace std;

TEST(sigma_PublicPrivateCoin_test, test)
{
    //creating params
    ParamsV3* params = sigma::ParamsV3::get_default();

    //testing public coin and serialize
    secp_primitives::GroupElement coin;
    coin.randomize();
    PublicCoinV3 publicCoin(coin, ZQ_GOLDWASSER);
    CDataStream serializedCoin(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoin << publicCoin;
    PublicCoinV3 publicCoinNew;
    serializedCoin >> publicCoinNew;
    EXPECT_TRUE(publicCoin == publicCoinNew);

    // mint test
    PrivateCoinV3 newCoin(params);
    PublicCoinV3 pubCoin = newCoin.getPublicCoin();
    EXPECT_TRUE(pubCoin.validate());
}
