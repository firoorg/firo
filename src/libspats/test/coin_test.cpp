#include "../coin.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spats {
    
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

    BOOST_FIXTURE_TEST_SUITE(spats_coin_tests, BasicTestingSetup)

    BOOST_AUTO_TEST_CASE(mint_identify_recover)
    {
        // Parameters
        const spark::Params* params;
        params = spark::Params::get_default();

        const Scalar asset_type = Scalar(uint64_t(1)); // new value
        const Scalar identifier = Scalar(uint64_t(1)); // new value
        const uint64_t i = 12345;
        const uint64_t v = 86;
        const std::string memo = "Spam and eggs are a tasty dish!"; // maximum length
        BOOST_CHECK_EQUAL(memo.size(), params->get_memo_bytes());

        // Generate keys
        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        // Generate address
        spark::Address address(incoming_view_key, i);

        // Generate coin
        Scalar k;
        k.randomize();
        Coin coin = Coin(
            params,
            COIN_TYPE_MINT,
            k,
            asset_type,
            identifier,
            address,
            v,
            memo,
            random_char_vector()
        );

        // Identify coin
        IdentifiedCoinData i_data = coin.identify(incoming_view_key);
        BOOST_CHECK_EQUAL(i_data.i, i);
        BOOST_CHECK_EQUAL_COLLECTIONS(i_data.d.begin(), i_data.d.end(), address.get_d().begin(), address.get_d().end());
        BOOST_CHECK_EQUAL(i_data.a, asset_type);
        BOOST_CHECK_EQUAL(i_data.iota, identifier);
        BOOST_CHECK_EQUAL(i_data.v, v);
        BOOST_CHECK_EQUAL(i_data.k, k);
        BOOST_CHECK_EQUAL(memo, i_data.memo);
        // Recover coin
        RecoveredCoinData r_data = coin.recover(full_view_key, i_data);
        BOOST_CHECK_EQUAL(
            params->get_F()*(spark::SparkUtils::hash_ser(k, coin.serial_context) + spark::SparkUtils::hash_Q2(incoming_view_key.get_s1(), i) + full_view_key.get_s2()) + full_view_key.get_D(),
            params->get_F()*r_data.s + full_view_key.get_D()
        );
        BOOST_CHECK_EQUAL(r_data.T*r_data.s + full_view_key.get_D(), params->get_U());
    }

    BOOST_AUTO_TEST_CASE(spend_identify_recover)
    {
        // Parameters
        const spark::Params* params;
        params = spark::Params::get_default();

        const Scalar asset_type = Scalar(uint64_t(0)); // new value
        const Scalar identifier = Scalar(uint64_t(0)); // new value
        const uint64_t i = 12345;
        const uint64_t v = 86;
        const std::string memo = "Memo";

        // Generate keys
        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        // Generate address
        spark::Address address(incoming_view_key, i);

        // Generate coin
        Scalar k;
        k.randomize();
        Coin coin = Coin(
            params,
            COIN_TYPE_MINT,
            k,
            asset_type,
            identifier,
            address,
            v,
            memo,
            random_char_vector()
        );

        // Identify coin
        IdentifiedCoinData i_data = coin.identify(incoming_view_key);
        BOOST_CHECK_EQUAL(i_data.i, i);
        BOOST_CHECK_EQUAL_COLLECTIONS(i_data.d.begin(), i_data.d.end(), address.get_d().begin(), address.get_d().end());
        BOOST_CHECK_EQUAL(i_data.a, asset_type);
        BOOST_CHECK_EQUAL(i_data.iota, identifier);
        BOOST_CHECK_EQUAL(i_data.v, v);
        BOOST_CHECK_EQUAL(i_data.k, k);
        BOOST_CHECK_EQUAL(memo.c_str(), i_data.memo.c_str());

        // Recover coin
        RecoveredCoinData r_data = coin.recover(full_view_key, i_data);
        BOOST_CHECK_EQUAL(
            params->get_F()*(spark::SparkUtils::hash_ser(k, coin.serial_context) + spark::SparkUtils::hash_Q2(incoming_view_key.get_s1(), i) + full_view_key.get_s2()) + full_view_key.get_D(),
            params->get_F()*r_data.s + full_view_key.get_D()
        );
        BOOST_CHECK_EQUAL(r_data.T*r_data.s + full_view_key.get_D(), params->get_U());
    }

    BOOST_AUTO_TEST_SUITE_END()

} // namespace spats
