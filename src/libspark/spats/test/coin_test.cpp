#include "../../coin.h"

#include "../../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spats {
    
    using namespace secp_primitives;
    using namespace spark;


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
        spark::Coin coin = spark::Coin(
            params,
            COIN_TYPE_MINT_V2,
            k,
            address,
            v,
            memo,
            random_char_vector(),
            asset_type,
            identifier
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
        spark::Coin coin = spark::Coin(
            params,
            COIN_TYPE_MINT_V2,
            k,
            address,
            v,
            memo,
            random_char_vector(),
            asset_type,
            identifier
        );

        // Identify coin
        IdentifiedCoinData i_data = coin.identify(incoming_view_key);
        BOOST_CHECK_EQUAL(i_data.i, i);
        BOOST_CHECK_EQUAL_COLLECTIONS(i_data.d.begin(), i_data.d.end(), address.get_d().begin(), address.get_d().end());
        BOOST_CHECK_EQUAL(i_data.a, asset_type);
        BOOST_CHECK_EQUAL(i_data.iota, identifier);
        BOOST_CHECK_EQUAL(i_data.v, v);
        BOOST_CHECK_EQUAL(i_data.k, k);
        BOOST_CHECK_EQUAL(i_data.memo, memo);

        // Recover coin
        RecoveredCoinData r_data = coin.recover(full_view_key, i_data);
        BOOST_CHECK_EQUAL(
            params->get_F()*(spark::SparkUtils::hash_ser(k, coin.serial_context) + spark::SparkUtils::hash_Q2(incoming_view_key.get_s1(), i) + full_view_key.get_s2()) + full_view_key.get_D(),
            params->get_F()*r_data.s + full_view_key.get_D()
        );
        BOOST_CHECK_EQUAL(r_data.T*r_data.s + full_view_key.get_D(), params->get_U());
    }

    // Test coin serialization roundtrip
    BOOST_AUTO_TEST_CASE(serialization_roundtrip)
    {
        const spark::Params* params = spark::Params::get_default();

        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        spark::Address address(incoming_view_key, 7777);

        Scalar k;
        k.randomize();
        spark::Coin original(
            params,
            COIN_TYPE_MINT_V2,
            k,
            address,
            500,
            "Test memo",
            random_char_vector(),
            Scalar(uint64_t(2)),
            Scalar(uint64_t(0))
        );

        // Serialize
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << original;

        // Deserialize
        spark::Coin deserialized;
        stream >> deserialized;
        deserialized.setSerialContext(original.serial_context);

        // Check equality
        BOOST_CHECK(original == deserialized);

        // Deserialized coin should be identifiable
        IdentifiedCoinData i_data = deserialized.identify(incoming_view_key);
        BOOST_CHECK_EQUAL(i_data.v, 500);
        BOOST_CHECK_EQUAL(i_data.a, Scalar(uint64_t(2)));
    }

    // Test wrong key cannot identify coin
    BOOST_AUTO_TEST_CASE(wrong_key_fails_identify)
    {
        const spark::Params* params = spark::Params::get_default();

        // Create two different key sets
        spark::SpendKey spend_key1(params);
        spark::FullViewKey full_view_key1(spend_key1);
        spark::IncomingViewKey incoming_view_key1(full_view_key1);

        spark::SpendKey spend_key2(params);
        spark::FullViewKey full_view_key2(spend_key2);
        spark::IncomingViewKey incoming_view_key2(full_view_key2);

        spark::Address address1(incoming_view_key1, 1111);

        Scalar k;
        k.randomize();
        spark::Coin coin(
            params,
            COIN_TYPE_MINT_V2,
            k,
            address1,
            1000,
            "Secret",
            random_char_vector(),
            Scalar(uint64_t(0)),
            Scalar(uint64_t(0))
        );

        // Coin created for key1 should be identifiable with key1
        IdentifiedCoinData i_data = coin.identify(incoming_view_key1);
        BOOST_CHECK_EQUAL(i_data.v, 1000);

        // Coin should NOT be identifiable with wrong key (key2)
        BOOST_CHECK_THROW(coin.identify(incoming_view_key2), std::runtime_error);
    }

    // Test different asset types
    BOOST_AUTO_TEST_CASE(different_asset_types)
    {
        const spark::Params* params = spark::Params::get_default();

        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        spark::Address address(incoming_view_key, 2222);

        // Test various asset types
        std::vector<uint64_t> asset_types = {0, 1, 2, 100, 1000000};

        for (uint64_t asset_type : asset_types) {
            Scalar k;
            k.randomize();
            spark::Coin coin(
                params,
                COIN_TYPE_MINT_V2,
                k,
                address,
                100,
                "Test",
                random_char_vector(),
                Scalar(asset_type),
                Scalar(uint64_t(0))
            );

            IdentifiedCoinData i_data = coin.identify(incoming_view_key);
            BOOST_CHECK_EQUAL(i_data.a, Scalar(asset_type));
        }
    }

    // Test coin type flags
    BOOST_AUTO_TEST_CASE(coin_type_flags)
    {
        const spark::Params* params = spark::Params::get_default();

        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        spark::Address address(incoming_view_key, 3333);

        Scalar k;
        k.randomize();

        // MINT_V2 coin
        spark::Coin mint_coin(
            params,
            COIN_TYPE_MINT_V2,
            k,
            address,
            100,
            "Mint",
            random_char_vector(),
            Scalar(uint64_t(0)),
            Scalar(uint64_t(0))
        );

        BOOST_CHECK(mint_coin.isMint());
        BOOST_CHECK(!mint_coin.isSpend());
        BOOST_CHECK(mint_coin.isValidType());
        BOOST_CHECK(mint_coin.isSpatsType());

        // SPEND_V2 coin
        spark::Coin spend_coin(
            params,
            COIN_TYPE_SPEND_V2,
            k,
            address,
            100,
            "Spend",
            random_char_vector(),
            Scalar(uint64_t(0)),
            Scalar(uint64_t(0))
        );

        BOOST_CHECK(!spend_coin.isMint());
        BOOST_CHECK(spend_coin.isSpend());
        BOOST_CHECK(spend_coin.isValidType());
        BOOST_CHECK(spend_coin.isSpatsType());
    }

    // Test zero value coin
    BOOST_AUTO_TEST_CASE(zero_value_coin)
    {
        const spark::Params* params = spark::Params::get_default();

        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        spark::Address address(incoming_view_key, 4444);

        Scalar k;
        k.randomize();
        spark::Coin coin(
            params,
            COIN_TYPE_MINT_V2,
            k,
            address,
            0, // zero value
            "Zero",
            random_char_vector(),
            Scalar(uint64_t(0)),
            Scalar(uint64_t(0))
        );

        IdentifiedCoinData i_data = coin.identify(incoming_view_key);
        BOOST_CHECK_EQUAL(i_data.v, 0);
    }

    // Test empty memo
    BOOST_AUTO_TEST_CASE(empty_memo)
    {
        const spark::Params* params = spark::Params::get_default();

        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        spark::Address address(incoming_view_key, 5555);

        Scalar k;
        k.randomize();
        spark::Coin coin(
            params,
            COIN_TYPE_MINT_V2,
            k,
            address,
            100,
            "", // empty memo
            random_char_vector(),
            Scalar(uint64_t(0)),
            Scalar(uint64_t(0))
        );

        IdentifiedCoinData i_data = coin.identify(incoming_view_key);
        BOOST_CHECK_EQUAL(i_data.memo, "");
    }

    // Test coin hash uniqueness
    BOOST_AUTO_TEST_CASE(coin_hash_uniqueness)
    {
        const spark::Params* params = spark::Params::get_default();

        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        spark::Address address(incoming_view_key, 6666);

        // Create two different coins
        Scalar k1, k2;
        k1.randomize();
        k2.randomize();

        spark::Coin coin1(params, COIN_TYPE_MINT_V2, k1, address, 100, "A",
            random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0)));
        spark::Coin coin2(params, COIN_TYPE_MINT_V2, k2, address, 100, "B",
            random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0)));

        // Hashes should be different
        BOOST_CHECK(coin1.getHash() != coin2.getHash());

        // Same coin should have same hash
        BOOST_CHECK(coin1.getHash() == coin1.getHash());
    }

    // Test coin inequality
    BOOST_AUTO_TEST_CASE(coin_inequality)
    {
        const spark::Params* params = spark::Params::get_default();

        spark::SpendKey spend_key(params);
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        spark::Address address(incoming_view_key, 8888);

        Scalar k1, k2;
        k1.randomize();
        k2.randomize();

        spark::Coin coin1(params, COIN_TYPE_MINT_V2, k1, address, 100, "Test",
            random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0)));
        spark::Coin coin2(params, COIN_TYPE_MINT_V2, k2, address, 100, "Test",
            random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0)));

        // Different coins should not be equal
        BOOST_CHECK(coin1 != coin2);

        // Same coin should be equal to itself
        BOOST_CHECK(coin1 == coin1);
    }

    BOOST_AUTO_TEST_SUITE_END()

} // namespace spats
