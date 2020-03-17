#include "../coin.h"
#include "../params.h"

#include "streams.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

BOOST_AUTO_TEST_SUITE(lelantus_coin_tests)

BOOST_AUTO_TEST_CASE(privatecoin)
{
    auto params = Params::get_default();

    Scalar v(1);

    // default constructor
    PrivateCoin priv(params, v);
    auto &serial = priv.getSerialNumber();
    auto &randomness = priv.getRandomness();

    // calculate commitment
    auto commitment = LelantusPrimitives<Scalar, GroupElement>::double_commit(
        params->get_g(), serial,
        params->get_h0(), priv.getV(),
        params->get_h1(), randomness);

    // verify
    BOOST_CHECK(serial.isMember());
    BOOST_CHECK(randomness.isMember());
    BOOST_CHECK_EQUAL(0, priv.getVersion());
    BOOST_CHECK_EQUAL(v, priv.getV());
    BOOST_CHECK_EQUAL(commitment, priv.getPublicCoin().getValue());

    // Construct the identical coin by another constructor
    PrivateCoin anotherPriv(params, serial, v, randomness, 0);

    // verify
    BOOST_CHECK_EQUAL(serial, anotherPriv.getSerialNumber());
    BOOST_CHECK_EQUAL(randomness, anotherPriv.getRandomness());
    BOOST_CHECK_EQUAL(0, anotherPriv.getVersion());
    BOOST_CHECK_EQUAL(v, anotherPriv.getV());
    BOOST_CHECK_EQUAL(commitment, anotherPriv.getPublicCoin().getValue());
}

BOOST_AUTO_TEST_CASE(privcoin_getset)
{
    auto const params = Params::get_default();

    PrivateCoin coin1(params, 1);
    PrivateCoin coin2(params, 2);

    BOOST_CHECK(coin1.getPublicCoin() != coin2.getPublicCoin());
    BOOST_CHECK(coin1.getRandomness() != coin2.getRandomness());
    BOOST_CHECK(coin1.getSerialNumber() != coin2.getSerialNumber());
    BOOST_CHECK(coin1.getV() != coin2.getV());

    // set
    coin2.setPublicCoin(coin1.getPublicCoin());
    coin2.setRandomness(coin1.getRandomness());
    coin2.setSerialNumber(coin1.getSerialNumber());
    coin2.setV(coin1.getV());
    coin2.setVersion(10);

    // verify
    BOOST_CHECK(coin1.getPublicCoin() == coin2.getPublicCoin());
    BOOST_CHECK(coin1.getRandomness() == coin2.getRandomness());
    BOOST_CHECK(coin1.getSerialNumber() == coin2.getSerialNumber());
    BOOST_CHECK(coin1.getV() == coin2.getV());
    BOOST_CHECK(10 == coin2.getVersion());
}

BOOST_AUTO_TEST_CASE(publiccoin_constructor)
{
    // default
    PublicCoin defaultPub;

    BOOST_CHECK(defaultPub.getValue().isInfinity());

    // specify commitment
    GroupElement coin;
    coin.randomize();
    PublicCoin pub(coin);

    BOOST_CHECK_EQUAL(coin, pub.getValue());
}

BOOST_AUTO_TEST_CASE(publiccoin_hash)
{
    // seed
    std::array<uint8_t, 32> seed; // 32 bytes of 0s
    std::fill(seed.begin(), seed.end(), 0);

    GroupElement r;
    r.generate(seed.data());

    PublicCoin coin(r);

    BOOST_CHECK(r.isMember() && !r.isInfinity());
    BOOST_CHECK_EQUAL(
        "c3ca472773e3334f057875b8268dabd16dcda3d2b4cad3e924ff8c31affacf67",
        coin.getValueHash().GetHex());
}

BOOST_AUTO_TEST_CASE(validate_publiccoin)
{
    // default pubcoin
    BOOST_CHECK(!PublicCoin().validate());

    // inf coin
    GroupElement infCoin;
    BOOST_CHECK(infCoin.isMember() && infCoin.isInfinity());
    BOOST_CHECK(!PublicCoin(infCoin).validate());

    // valid coin
    GroupElement coin;
    coin.randomize();
    BOOST_CHECK(coin.isMember() && !coin.isInfinity());
    BOOST_CHECK(PublicCoin(coin).validate());
}

BOOST_AUTO_TEST_CASE(publiccoin_equality)
{
    GroupElement a, b;
    a.randomize();
    b.randomize();

    PublicCoin pubA(a);
    PublicCoin pubB(b);
    PublicCoin pubC(a);

    BOOST_CHECK(pubA == pubA);
    BOOST_CHECK(pubA == pubC);
    BOOST_CHECK(pubA != pubB);
}

BOOST_AUTO_TEST_CASE(publiccoin_serialization)
{
    GroupElement coin;
    coin.randomize();

    PublicCoin pub(coin);

    CDataStream serialize(SER_NETWORK, PROTOCOL_VERSION);
    serialize << pub;

    CDataStream deserialize(
        std::vector<unsigned char>(serialize.begin(), serialize.end()),
        SER_NETWORK, PROTOCOL_VERSION);

    PublicCoin deserializedCoin;
    deserialize >> deserializedCoin;

    BOOST_CHECK(pub == deserializedCoin);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus