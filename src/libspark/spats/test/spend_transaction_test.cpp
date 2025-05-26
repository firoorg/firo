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
        out_coin_data);


    // Verify
    transaction.setCoverSets(cover_set_data);
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace spats
