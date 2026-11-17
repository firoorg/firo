#include "../coin.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

using namespace secp_primitives;

// Generate a random char vector from a random scalar
static std::vector<unsigned char> random_char_vector() {
    Scalar temp;
    temp.randomize();
    std::vector<unsigned char> result;
    result.resize(SCALAR_ENCODING);
    temp.serialize(result.data());

    return result;
}

BOOST_FIXTURE_TEST_SUITE(spark_coin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mint_identify_recover)
{
    // Parameters
    const Params* params;
    params = Params::get_default();
    
    const uint64_t i = 12345;
    const uint64_t v = 86;
    const std::string memo = "Spam and eggs are a tasty dish!"; // maximum length
    BOOST_CHECK_EQUAL(memo.size(), params->get_memo_bytes());

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    Address address(incoming_view_key, i);

    // Generate coin
    Scalar k;
    k.randomize();
    Coin coin = Coin(
        params,
        COIN_TYPE_MINT,
        k,
        address,
        v,
        memo,
        random_char_vector()
    );

    // Identify coin
    IdentifiedCoinData i_data = coin.identify(incoming_view_key);
    BOOST_CHECK_EQUAL(i_data.i, i);
    BOOST_CHECK_EQUAL_COLLECTIONS(i_data.d.begin(), i_data.d.end(), address.get_d().begin(), address.get_d().end());
    BOOST_CHECK_EQUAL(i_data.v, v);
    BOOST_CHECK_EQUAL(i_data.k, k);
    BOOST_CHECK_EQUAL(i_data.memo, memo);

    // Recover coin
    RecoveredCoinData r_data = coin.recover(full_view_key, i_data);
    BOOST_CHECK_EQUAL(
        params->get_F()*(SparkUtils::hash_ser(k, coin.serial_context) + SparkUtils::hash_Q2(incoming_view_key.get_s1(), i) + full_view_key.get_s2()) + full_view_key.get_D(),
        params->get_F()*r_data.s + full_view_key.get_D()
    );
    BOOST_CHECK_EQUAL(r_data.T*r_data.s + full_view_key.get_D(), params->get_U());
}

BOOST_AUTO_TEST_CASE(identify_rejects_a_diversifier_of_another_length)
{
    // Whoever holds the incoming view key can make a coin whose recipient data
    // decrypts and carries a diversifier of another length: one byte less, and a
    // trailing byte to keep the length the data must have. It is not a coin of the
    // key, and fails the way a foreign coin does, which is all that callers expect.
    const Params* params = Params::get_default();
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);
    Address address(incoming_view_key, 1);

    Scalar k;
    k.randomize();
    Coin coin(params, COIN_TYPE_MINT, k, address, 86, "", random_char_vector());
    BOOST_CHECK_EQUAL(coin.identify(incoming_view_key).i, 1);

    MintCoinRecipientData r;
    r.d = address.get_d();
    r.d.pop_back();
    r.k = k;
    r.padded_memo = std::string(params->get_memo_bytes() + 1, '\0');
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << r << static_cast<unsigned char>(0);
    coin.K = SparkUtils::hash_div(r.d)*SparkUtils::hash_k(k);
    coin.r_ = AEAD::encrypt(coin.K*incoming_view_key.get_s1(), "Mint coin data", stream);
    BOOST_CHECK_THROW(coin.identify(incoming_view_key), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(spend_identify_recover)
{
    // Parameters
    const Params* params;
    params = Params::get_default();
    
    const uint64_t i = 12345;
    const uint64_t v = 86;
    const std::string memo = "Spam and eggs";

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    Address address(incoming_view_key, i);

    // Generate coin
    Scalar k;
    k.randomize();
    Coin coin = Coin(
        params,
        COIN_TYPE_SPEND,
        k,
        address,
        v,
        memo,
        random_char_vector()
    );

    // Identify coin
    IdentifiedCoinData i_data = coin.identify(incoming_view_key);
    BOOST_CHECK_EQUAL(i_data.i, i);
    BOOST_CHECK_EQUAL_COLLECTIONS(i_data.d.begin(), i_data.d.end(), address.get_d().begin(), address.get_d().end());
    BOOST_CHECK_EQUAL(i_data.v, v);
    BOOST_CHECK_EQUAL(i_data.k, k);
    BOOST_CHECK_EQUAL(i_data.memo, memo);

    // Recover coin
    RecoveredCoinData r_data = coin.recover(full_view_key, i_data);
    BOOST_CHECK_EQUAL(
        params->get_F()*(SparkUtils::hash_ser(k, coin.serial_context) + SparkUtils::hash_Q2(incoming_view_key.get_s1(), i) + full_view_key.get_s2()) + full_view_key.get_D(),
        params->get_F()*r_data.s + full_view_key.get_D()
    );
    BOOST_CHECK_EQUAL(r_data.T*r_data.s + full_view_key.get_D(), params->get_U());
}
BOOST_AUTO_TEST_SUITE_END()

}
