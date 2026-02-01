#include "../spend_transaction.h"

#include "../../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spats
{

// Useful scalar constants
const Scalar ZERO = Scalar((uint64_t)0);
const Scalar ONE = Scalar((uint64_t)1);

using namespace secp_primitives;
using namespace spark;

// Generate a random char vector from a random scalar
static std::vector<unsigned char> random_char_vector()
{
    Scalar temp;
    temp.randomize();
    std::vector<unsigned char> result;
    result.resize(SCALAR_ENCODING);
    temp.serialize(result.data());

    return result;
}

BOOST_FIXTURE_TEST_SUITE(spats_spend_transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(generate_verify)
{
    // Parameters
    const spark::Params* params;
    params = spark::Params::get_test();

    const std::string memo = "Spam and eggs"; // arbitrary memo

    // Generate keys
    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    spark::Address address(incoming_view_key, i);

    // Mint some coins to the address
    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());

    std::vector<spark::Coin> in_coins;
    for (std::size_t i = 0; i < N / 2; i++) {
        Scalar k;
        k.randomize();

        uint64_t v = 123 + i; // arbitrary value


        const uint64_t asset_type = 0; // new value
        const uint64_t identifier = 0; // new value


        in_coins.emplace_back(spark::Coin(
            params,
            COIN_TYPE_MINT_V2,
            k,

            address,
            v,
            memo,
            random_char_vector(),
            asset_type,
            identifier));
    }

    for (std::size_t i = N / 2; i < N; i++) {
        Scalar k;
        k.randomize();

        uint64_t v = 123 + i; // arbitrary value


        const uint64_t asset_type = 1; // new value
        const uint64_t identifier = 0; // new value


        in_coins.emplace_back(spark::Coin(
            params,
            COIN_TYPE_MINT_V2,
            k,
            address,
            v,
            memo,
            random_char_vector(),
            asset_type,
            identifier));
    }


    // Track values so we can set the fee to make the transaction balance
    uint64_t f = 0;

    // Choose coins to spend, recover them, and prepare them for spending
    std::vector<std::size_t> spend_indices = {1, 3, 5};

    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    const std::size_t w = spend_indices.size();
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;

    for (std::size_t u = 0; u < w; u++) {
        IdentifiedCoinData identified_coin_data = in_coins[spend_indices[u]].identify(incoming_view_key);
        RecoveredCoinData recovered_coin_data = in_coins[spend_indices[u]].recover(full_view_key, identified_coin_data);

        spend_coin_data.emplace_back();
        uint64_t cover_set_id = 31415;
        spend_coin_data.back().cover_set_id = cover_set_id;

        CoverSetData setData;
        setData.cover_set_size = in_coins.size();
        setData.cover_set_representation = random_char_vector();
        cover_set_data[cover_set_id] = setData;
        cover_sets[cover_set_id] = in_coins;
        spend_coin_data.back().index = spend_indices[u];
        spend_coin_data.back().k = identified_coin_data.k;
        spend_coin_data.back().s = recovered_coin_data.s;
        spend_coin_data.back().T = recovered_coin_data.T;
        spend_coin_data.back().v = identified_coin_data.v;
        spend_coin_data.back().a = identified_coin_data.a;
        spend_coin_data.back().iota = identified_coin_data.iota;


        f += identified_coin_data.v;
    }

    std::vector<std::size_t> spend_indices_generic = {N / 2 + 2, N / 2 + 3};

    const std::size_t w_generic = spend_indices_generic.size();

    for (std::size_t u = 0; u < w_generic; u++) {
        IdentifiedCoinData identified_coin_data = in_coins[spend_indices_generic[u]].identify(incoming_view_key);
        RecoveredCoinData recovered_coin_data = in_coins[spend_indices_generic[u]].recover(full_view_key, identified_coin_data);

        spend_coin_data.emplace_back();
        uint64_t cover_set_id = 31415;
        spend_coin_data.back().cover_set_id = cover_set_id;

        CoverSetData setData;
        setData.cover_set_size = in_coins.size();
        setData.cover_set_representation = random_char_vector();
        cover_set_data[cover_set_id] = setData;
        cover_sets[cover_set_id] = in_coins;
        spend_coin_data.back().index = spend_indices_generic[u];
        spend_coin_data.back().k = identified_coin_data.k;
        spend_coin_data.back().s = recovered_coin_data.s;
        spend_coin_data.back().T = recovered_coin_data.T;
        spend_coin_data.back().v = identified_coin_data.v;
        spend_coin_data.back().a = identified_coin_data.a;
        spend_coin_data.back().iota = identified_coin_data.iota;
    }

    // Generate new output coins and compute the fee
    const std::size_t t = 3;
    std::vector<OutputCoinData> out_coin_data;
    for (std::size_t j = 0; j < t; j++) {
        out_coin_data.emplace_back();
        out_coin_data.back().address = address;
        out_coin_data.back().v = 12 + j; // arbitrary value
        out_coin_data.back().memo = memo;
        out_coin_data.back().a = ZERO;    // asset type
        out_coin_data.back().iota = ZERO; // identifier

        f -= out_coin_data.back().v;
    }

    const std::size_t t_generic = 2;
    for (std::size_t j = 0; j < t_generic; j++) {
        out_coin_data.emplace_back();
        out_coin_data.back().address = address;
        out_coin_data.back().v = 123 + spend_indices_generic[j]; // arbitrary value
        out_coin_data.back().memo = memo;
        out_coin_data.back().a = ONE;    // asset type
        out_coin_data.back().iota = ZERO; // identifier
    }


    // Assert the fee is correct
    uint64_t fee_test = f;
    for (std::size_t j = 0; j < t; j++) {
        fee_test += out_coin_data[j].v;
    }
    for (std::size_t u = 0; u < w; u++) {
        fee_test -= spend_coin_data[u].v;
    }


    if (fee_test != 0) {
        throw std::runtime_error("Bad fee assertion");
    }

    // Generate spend transaction
    SpendTransaction transaction(
        params,
        full_view_key,
        spend_key,
        spend_coin_data,
        cover_set_data,
        cover_sets,
        f,
        0,
        0,
        out_coin_data);


    // Verify
    transaction.setCoverSets(cover_set_data);
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));
}

// Test base-only transaction (no asset coins, only base currency)
BOOST_AUTO_TEST_CASE(base_only_transaction)
{
    // Parameters
    const spark::Params* params = spark::Params::get_test();
    const std::string memo = "Base only test";

    // Generate keys
    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    spark::Address address(incoming_view_key, i);

    // Mint base coins only (asset_type = 0)
    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<spark::Coin> in_coins;
    for (std::size_t idx = 0; idx < N; idx++) {
        Scalar k;
        k.randomize();
        uint64_t v = 100 + idx;
        in_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, v, memo,
            random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0))));
    }

    // Prepare spend data - spend 2 base coins
    std::vector<std::size_t> spend_indices = {1, 3};
    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
    uint64_t total_input = 0;

    for (std::size_t u = 0; u < spend_indices.size(); u++) {
        IdentifiedCoinData id_data = in_coins[spend_indices[u]].identify(incoming_view_key);
        RecoveredCoinData rec_data = in_coins[spend_indices[u]].recover(full_view_key, id_data);

        spend_coin_data.emplace_back();
        uint64_t cover_set_id = 1000;
        spend_coin_data.back().cover_set_id = cover_set_id;
        spend_coin_data.back().index = spend_indices[u];
        spend_coin_data.back().k = id_data.k;
        spend_coin_data.back().s = rec_data.s;
        spend_coin_data.back().T = rec_data.T;
        spend_coin_data.back().v = id_data.v;
        spend_coin_data.back().a = id_data.a;
        spend_coin_data.back().iota = id_data.iota;

        CoverSetData setData;
        setData.cover_set_size = in_coins.size();
        setData.cover_set_representation = random_char_vector();
        cover_set_data[cover_set_id] = setData;
        cover_sets[cover_set_id] = in_coins;

        total_input += id_data.v;
    }

    // Create outputs - 2 base outputs
    std::vector<OutputCoinData> out_coin_data;
    uint64_t total_output = 0;
    for (std::size_t j = 0; j < 2; j++) {
        out_coin_data.emplace_back();
        out_coin_data.back().address = address;
        out_coin_data.back().v = 50 + j;
        out_coin_data.back().memo = memo;
        out_coin_data.back().a = ZERO;
        out_coin_data.back().iota = ZERO;
        total_output += out_coin_data.back().v;
    }

    uint64_t fee = total_input - total_output;

    // Generate and verify
    SpendTransaction transaction(
        params, full_view_key, spend_key, spend_coin_data,
        cover_set_data, cover_sets, fee, 0, 0, out_coin_data);

    transaction.setCoverSets(cover_set_data);
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));
}

// Test single input single output transaction
BOOST_AUTO_TEST_CASE(single_input_output)
{
    const spark::Params* params = spark::Params::get_test();
    const std::string memo = "Single";

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    const uint64_t i = 999;
    spark::Address address(incoming_view_key, i);

    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<spark::Coin> in_coins;
    for (std::size_t idx = 0; idx < N; idx++) {
        Scalar k;
        k.randomize();
        uint64_t v = 1000;
        in_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, v, memo,
            random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0))));
    }

    // Single input
    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;

    IdentifiedCoinData id_data = in_coins[0].identify(incoming_view_key);
    RecoveredCoinData rec_data = in_coins[0].recover(full_view_key, id_data);

    spend_coin_data.emplace_back();
    uint64_t cover_set_id = 2000;
    spend_coin_data.back().cover_set_id = cover_set_id;
    spend_coin_data.back().index = 0;
    spend_coin_data.back().k = id_data.k;
    spend_coin_data.back().s = rec_data.s;
    spend_coin_data.back().T = rec_data.T;
    spend_coin_data.back().v = id_data.v;
    spend_coin_data.back().a = id_data.a;
    spend_coin_data.back().iota = id_data.iota;

    CoverSetData setData;
    setData.cover_set_size = in_coins.size();
    setData.cover_set_representation = random_char_vector();
    cover_set_data[cover_set_id] = setData;
    cover_sets[cover_set_id] = in_coins;

    // Single output
    std::vector<OutputCoinData> out_coin_data;
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = 900;
    out_coin_data.back().memo = memo;
    out_coin_data.back().a = ZERO;
    out_coin_data.back().iota = ZERO;

    uint64_t fee = 1000 - 900; // 100

    SpendTransaction transaction(
        params, full_view_key, spend_key, spend_coin_data,
        cover_set_data, cover_sets, fee, 0, 0, out_coin_data);

    transaction.setCoverSets(cover_set_data);
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));
}

// Test transaction with burn functionality
BOOST_AUTO_TEST_CASE(transaction_with_burn)
{
    const spark::Params* params = spark::Params::get_test();
    const std::string memo = "Burn test";

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    const uint64_t i = 5555;
    spark::Address address(incoming_view_key, i);

    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());

    // Create base coins and asset coins
    std::vector<spark::Coin> in_coins;
    // Base coins (first half)
    for (std::size_t idx = 0; idx < N / 2; idx++) {
        Scalar k;
        k.randomize();
        in_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, 200,
            memo, random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0))));
    }
    // Asset coins (second half) with asset_type = 2
    for (std::size_t idx = N / 2; idx < N; idx++) {
        Scalar k;
        k.randomize();
        in_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, 500,
            memo, random_char_vector(), Scalar(uint64_t(2)), Scalar(uint64_t(0))));
    }

    // Spend 1 base coin and 1 asset coin
    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;

    // Base coin input
    {
        IdentifiedCoinData id_data = in_coins[1].identify(incoming_view_key);
        RecoveredCoinData rec_data = in_coins[1].recover(full_view_key, id_data);
        spend_coin_data.emplace_back();
        uint64_t cover_set_id = 3000;
        spend_coin_data.back().cover_set_id = cover_set_id;
        spend_coin_data.back().index = 1;
        spend_coin_data.back().k = id_data.k;
        spend_coin_data.back().s = rec_data.s;
        spend_coin_data.back().T = rec_data.T;
        spend_coin_data.back().v = id_data.v;
        spend_coin_data.back().a = id_data.a;
        spend_coin_data.back().iota = id_data.iota;

        CoverSetData setData;
        setData.cover_set_size = in_coins.size();
        setData.cover_set_representation = random_char_vector();
        cover_set_data[cover_set_id] = setData;
        cover_sets[cover_set_id] = in_coins;
    }

    // Asset coin input
    {
        std::size_t asset_idx = N / 2 + 1;
        IdentifiedCoinData id_data = in_coins[asset_idx].identify(incoming_view_key);
        RecoveredCoinData rec_data = in_coins[asset_idx].recover(full_view_key, id_data);
        spend_coin_data.emplace_back();
        uint64_t cover_set_id = 3000;
        spend_coin_data.back().cover_set_id = cover_set_id;
        spend_coin_data.back().index = asset_idx;
        spend_coin_data.back().k = id_data.k;
        spend_coin_data.back().s = rec_data.s;
        spend_coin_data.back().T = rec_data.T;
        spend_coin_data.back().v = id_data.v;
        spend_coin_data.back().a = id_data.a;
        spend_coin_data.back().iota = id_data.iota;
    }

    // Outputs: 1 base output, 1 asset output (with burn)
    std::vector<OutputCoinData> out_coin_data;

    // Base output
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = 100;
    out_coin_data.back().memo = memo;
    out_coin_data.back().a = ZERO;
    out_coin_data.back().iota = ZERO;

    // Asset output (less than input, difference is burned)
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = 400; // 500 input - 400 output = 100 burn
    out_coin_data.back().memo = memo;
    out_coin_data.back().a = Scalar(uint64_t(2));
    out_coin_data.back().iota = ZERO;

    uint64_t fee = 200 - 100; // base: 200 in, 100 out, fee = 100
    uint64_t burn = 500 - 400; // asset: 500 in, 400 out, burn = 100

    SpendTransaction transaction(
        params, full_view_key, spend_key, spend_coin_data,
        cover_set_data, cover_sets, fee, 0, burn, out_coin_data);

    transaction.setCoverSets(cover_set_data);
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));
}

// Test serialization roundtrip
BOOST_AUTO_TEST_CASE(serialization_roundtrip)
{
    const spark::Params* params = spark::Params::get_test();
    const std::string memo = "Serialize test";

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    spark::Address address(incoming_view_key, 7777);

    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<spark::Coin> in_coins;
    for (std::size_t idx = 0; idx < N; idx++) {
        Scalar k;
        k.randomize();
        in_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, 500,
            memo, random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0))));
    }

    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;

    IdentifiedCoinData id_data = in_coins[2].identify(incoming_view_key);
    RecoveredCoinData rec_data = in_coins[2].recover(full_view_key, id_data);

    spend_coin_data.emplace_back();
    uint64_t cover_set_id = 4000;
    spend_coin_data.back().cover_set_id = cover_set_id;
    spend_coin_data.back().index = 2;
    spend_coin_data.back().k = id_data.k;
    spend_coin_data.back().s = rec_data.s;
    spend_coin_data.back().T = rec_data.T;
    spend_coin_data.back().v = id_data.v;
    spend_coin_data.back().a = id_data.a;
    spend_coin_data.back().iota = id_data.iota;

    CoverSetData setData;
    setData.cover_set_size = in_coins.size();
    setData.cover_set_representation = random_char_vector();
    cover_set_data[cover_set_id] = setData;
    cover_sets[cover_set_id] = in_coins;

    std::vector<OutputCoinData> out_coin_data;
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = 400;
    out_coin_data.back().memo = memo;
    out_coin_data.back().a = ZERO;
    out_coin_data.back().iota = ZERO;

    uint64_t fee = 100;

    SpendTransaction original(
        params, full_view_key, spend_key, spend_coin_data,
        cover_set_data, cover_sets, fee, 0, 0, out_coin_data);

    // Serialize
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << original;

    // Deserialize
    SpendTransaction deserialized(params);
    serialized >> deserialized;

    // Set required data for verification
    deserialized.setOutCoins(original.getOutCoins());
    deserialized.setCoverSets(cover_set_data);

    // Verify deserialized transaction
    BOOST_CHECK(SpendTransaction::verify(deserialized, cover_sets));
}

// Test that tampered proof fails verification
BOOST_AUTO_TEST_CASE(tampered_proof_fails)
{
    const spark::Params* params = spark::Params::get_test();
    const std::string memo = "Tamper test";

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    spark::Address address(incoming_view_key, 8888);

    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<spark::Coin> in_coins;
    for (std::size_t idx = 0; idx < N; idx++) {
        Scalar k;
        k.randomize();
        in_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, 1000,
            memo, random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0))));
    }

    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;

    IdentifiedCoinData id_data = in_coins[5].identify(incoming_view_key);
    RecoveredCoinData rec_data = in_coins[5].recover(full_view_key, id_data);

    spend_coin_data.emplace_back();
    uint64_t cover_set_id = 5000;
    spend_coin_data.back().cover_set_id = cover_set_id;
    spend_coin_data.back().index = 5;
    spend_coin_data.back().k = id_data.k;
    spend_coin_data.back().s = rec_data.s;
    spend_coin_data.back().T = rec_data.T;
    spend_coin_data.back().v = id_data.v;
    spend_coin_data.back().a = id_data.a;
    spend_coin_data.back().iota = id_data.iota;

    CoverSetData setData;
    setData.cover_set_size = in_coins.size();
    setData.cover_set_representation = random_char_vector();
    cover_set_data[cover_set_id] = setData;
    cover_sets[cover_set_id] = in_coins;

    std::vector<OutputCoinData> out_coin_data;
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = 800;
    out_coin_data.back().memo = memo;
    out_coin_data.back().a = ZERO;
    out_coin_data.back().iota = ZERO;

    uint64_t fee = 200;

    SpendTransaction transaction(
        params, full_view_key, spend_key, spend_coin_data,
        cover_set_data, cover_sets, fee, 0, 0, out_coin_data);

    transaction.setCoverSets(cover_set_data);

    // Valid transaction should verify
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));

    // Tamper with output coins - change value
    std::vector<spark::Coin> tampered_out_coins = transaction.getOutCoins();
    // Create a different coin with wrong value
    Scalar evil_k;
    evil_k.randomize();
    spark::Coin evil_coin(params, COIN_TYPE_SPEND_V2, evil_k, address, 900, memo,
        random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0)));
    tampered_out_coins[0] = evil_coin;

    SpendTransaction tampered_tx(params);

    // Serialize original, deserialize to tampered
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << transaction;
    stream >> tampered_tx;

    tampered_tx.setOutCoins(tampered_out_coins);
    tampered_tx.setCoverSets(cover_set_data);

    // Tampered transaction should fail verification
    BOOST_CHECK(!SpendTransaction::verify(tampered_tx, cover_sets));
}

// Test verification with wrong cover set fails
BOOST_AUTO_TEST_CASE(wrong_cover_set_fails)
{
    const spark::Params* params = spark::Params::get_test();
    const std::string memo = "Wrong cover set";

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    spark::Address address(incoming_view_key, 9999);

    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<spark::Coin> in_coins;
    for (std::size_t idx = 0; idx < N; idx++) {
        Scalar k;
        k.randomize();
        in_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, 750,
            memo, random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0))));
    }

    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;

    IdentifiedCoinData id_data = in_coins[3].identify(incoming_view_key);
    RecoveredCoinData rec_data = in_coins[3].recover(full_view_key, id_data);

    spend_coin_data.emplace_back();
    uint64_t cover_set_id = 6000;
    spend_coin_data.back().cover_set_id = cover_set_id;
    spend_coin_data.back().index = 3;
    spend_coin_data.back().k = id_data.k;
    spend_coin_data.back().s = rec_data.s;
    spend_coin_data.back().T = rec_data.T;
    spend_coin_data.back().v = id_data.v;
    spend_coin_data.back().a = id_data.a;
    spend_coin_data.back().iota = id_data.iota;

    CoverSetData setData;
    setData.cover_set_size = in_coins.size();
    setData.cover_set_representation = random_char_vector();
    cover_set_data[cover_set_id] = setData;
    cover_sets[cover_set_id] = in_coins;

    std::vector<OutputCoinData> out_coin_data;
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = 650;
    out_coin_data.back().memo = memo;
    out_coin_data.back().a = ZERO;
    out_coin_data.back().iota = ZERO;

    uint64_t fee = 100;

    SpendTransaction transaction(
        params, full_view_key, spend_key, spend_coin_data,
        cover_set_data, cover_sets, fee, 0, 0, out_coin_data);

    transaction.setCoverSets(cover_set_data);

    // Valid cover set should verify
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));

    // Create wrong cover set with different coins
    std::unordered_map<uint64_t, std::vector<spark::Coin>> wrong_cover_sets;
    std::vector<spark::Coin> wrong_coins;
    for (std::size_t idx = 0; idx < N; idx++) {
        Scalar k;
        k.randomize();
        wrong_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, 999,
            memo, random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0))));
    }
    wrong_cover_sets[cover_set_id] = wrong_coins;

    // Wrong cover set should fail verification
    BOOST_CHECK(!SpendTransaction::verify(transaction, wrong_cover_sets));
}

// Test maximum value boundary
BOOST_AUTO_TEST_CASE(max_value_boundary)
{
    const spark::Params* params = spark::Params::get_test();
    const std::string memo = "Max value";

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    spark::Address address(incoming_view_key, 1111);

    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<spark::Coin> in_coins;

    // Use a large but valid value (not max to avoid overflow issues)
    uint64_t large_value = 1000000000000ULL; // 1 trillion

    for (std::size_t idx = 0; idx < N; idx++) {
        Scalar k;
        k.randomize();
        in_coins.emplace_back(spark::Coin(
            params, COIN_TYPE_MINT_V2, k, address, large_value,
            memo, random_char_vector(), Scalar(uint64_t(0)), Scalar(uint64_t(0))));
    }

    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;

    IdentifiedCoinData id_data = in_coins[0].identify(incoming_view_key);
    RecoveredCoinData rec_data = in_coins[0].recover(full_view_key, id_data);

    spend_coin_data.emplace_back();
    uint64_t cover_set_id = 7000;
    spend_coin_data.back().cover_set_id = cover_set_id;
    spend_coin_data.back().index = 0;
    spend_coin_data.back().k = id_data.k;
    spend_coin_data.back().s = rec_data.s;
    spend_coin_data.back().T = rec_data.T;
    spend_coin_data.back().v = id_data.v;
    spend_coin_data.back().a = id_data.a;
    spend_coin_data.back().iota = id_data.iota;

    CoverSetData setData;
    setData.cover_set_size = in_coins.size();
    setData.cover_set_representation = random_char_vector();
    cover_set_data[cover_set_id] = setData;
    cover_sets[cover_set_id] = in_coins;

    std::vector<OutputCoinData> out_coin_data;
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = large_value - 1000; // small fee
    out_coin_data.back().memo = memo;
    out_coin_data.back().a = ZERO;
    out_coin_data.back().iota = ZERO;

    uint64_t fee = 1000;

    SpendTransaction transaction(
        params, full_view_key, spend_key, spend_coin_data,
        cover_set_data, cover_sets, fee, 0, 0, out_coin_data);

    transaction.setCoverSets(cover_set_data);
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace spats
