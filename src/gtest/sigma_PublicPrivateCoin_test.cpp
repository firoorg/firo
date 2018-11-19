#include <gtest/gtest.h>
#include <libzerocoin/sigma/Coin.h>
#include <libzerocoin/sigma/Params.h>
#include "../streams.h"

using namespace sigma;
using namespace std;

TEST(sigma_PublicPrivateCoin_test, test)
{
    //creating params
    V3Params* params = sigma::V3Params::get_default();

    //testing public coin and serialize
    secp_primitives::GroupElement coin;
    coin.randomize();
    V3PublicCoin publicCoin(coin, ZQ_GOLDWASSER);
    CDataStream serializedCoin(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoin << publicCoin;
    V3PublicCoin publicCoinNew(serializedCoin);
    EXPECT_TRUE(publicCoin == publicCoinNew);

    // mint test
    V3PrivateCoin newCoin(params);
    V3PublicCoin pubCoin = newCoin.getPublicCoin();
    EXPECT_TRUE(pubCoin.validate());
}