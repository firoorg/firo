#include "../spend_transaction.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>
#include <new>

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

BOOST_FIXTURE_TEST_SUITE(spark_spend_transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(historical_multi_input_verification_is_explicit)
{
    // Parameters
    const Params* params;
    params = Params::get_test();

    const std::string memo = "Spam and eggs"; // arbitrary memo

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    Address address(incoming_view_key, i);

    // Mint some coins to the address
    std::size_t N = (std::size_t) pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<Coin> in_coins;
    for (std::size_t i = 0; i < N; i++) {
        Scalar k;
        k.randomize();

        uint64_t v = 123 + i; // arbitrary value

        in_coins.emplace_back(Coin(
            params,
            COIN_TYPE_MINT,
            k,
            address,
            v,
            memo,
            random_char_vector()
        ));
    }

    // Track values so we can set the fee to make the transaction balance
    uint64_t f = 0;

    // Choose coins to spend, recover them, and prepare them for spending
    std::vector<std::size_t> spend_indices = { 1, 3, 5 };
    std::vector<InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    const std::size_t w = spend_indices.size();
    std::unordered_map<uint64_t, std::vector<Coin>> cover_sets;
    const std::vector<unsigned char> shared_cover_set_representation =
        random_char_vector();

    for (std::size_t u = 0; u < w; u++) {
        IdentifiedCoinData identified_coin_data = in_coins[spend_indices[u]].identify(incoming_view_key);
        RecoveredCoinData recovered_coin_data = in_coins[spend_indices[u]].recover(full_view_key, identified_coin_data);

        spend_coin_data.emplace_back();
        // Use two identifiers that intentionally resolve to the same set. The
        // ordered input-to-set association must still be authenticated.
        uint64_t cover_set_id = 31415 + (u % 2);
        spend_coin_data.back().cover_set_id = cover_set_id;

        CoverSetData setData;
        setData.cover_set_size = in_coins.size();
        setData.cover_set_representation = shared_cover_set_representation;
        cover_set_data[cover_set_id] = setData;
        cover_sets[cover_set_id] = in_coins;
        spend_coin_data.back().index = spend_indices[u];
        spend_coin_data.back().k = identified_coin_data.k;
        spend_coin_data.back().s = recovered_coin_data.s;
        spend_coin_data.back().T = recovered_coin_data.T;
        spend_coin_data.back().v = identified_coin_data.v;

        f += identified_coin_data.v;
    }

    // Generate new output coins and compute the fee
    const std::size_t t = 3;
    std::vector<OutputCoinData> out_coin_data;
    for (std::size_t j = 0; j < t; j++) {
        out_coin_data.emplace_back();
        out_coin_data.back().address = address;
        out_coin_data.back().v = 12 + j; // arbitrary value
        out_coin_data.back().memo = memo;

        f -= out_coin_data.back().v;
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
        out_coin_data
    );

    // Pre-activation spends remain verifiable only through the historical
    // path. The default verifier applies the current single-input rule.
    transaction.setCoverSets(cover_set_data);
    BOOST_REQUIRE(SpendTransaction::verifyHistorical(
        transaction, cover_sets));
    BOOST_CHECK(!SpendTransaction::verify(transaction, cover_sets));

    // V2 uses the componentwise relation and is valid for the same honest
    // multi-input witness. Its payload starts with an explicit version and is
    // parsed only when the transaction type selects V2.
    std::map<uint64_t, uint256> blockHashes;
    for (const auto& entry : cover_set_data) {
        blockHashes.emplace(entry.first, uint256S("01"));
    }
    SpendTransaction transactionV2(
        params,
        full_view_key,
        spend_key,
        spend_coin_data,
        cover_set_data,
        cover_sets,
        f,
        0,
        out_coin_data,
        SpendTransactionVersion::V2,
        uint256S("01"),
        blockHashes);
    transactionV2.setCoverSets(cover_set_data);
    BOOST_REQUIRE(SpendTransaction::verify(transactionV2, cover_sets));

    std::size_t providerCalls = 0;
    const SpendTransaction::CoverSetProvider provider =
        [&cover_sets, &providerCalls](uint64_t id)
            -> const std::vector<Coin>& {
        ++providerCalls;
        return cover_sets.at(id);
    };
    BOOST_CHECK(SpendTransaction::verify(
        params, {transactionV2}, provider));
    BOOST_CHECK_EQUAL(providerCalls, cover_sets.size());

    const SpendTransaction::CoverSetProvider allocationFailure =
        [](uint64_t) -> const std::vector<Coin>& {
        throw std::bad_alloc();
    };
    BOOST_CHECK_THROW(
        SpendTransaction::verify(
            params, {transactionV2}, allocationFailure),
        std::bad_alloc);

    // V2 must authorize the exact serialized cover-set reference map. Even
    // when two reference blocks happen to resolve to the same cover set, a
    // third party must not be able to change the txid without invalidating the
    // proof.
    SpendTransaction changedReferences(transactionV2);
    auto replacementReferences = blockHashes;
    replacementReferences.begin()->second = uint256S("02");
    changedReferences.setBlockHashes(replacementReferences);
    BOOST_CHECK(!SpendTransaction::verify(changedReferences, cover_sets));

    CDataStream encodedV2(SER_NETWORK, PROTOCOL_VERSION);
    encodedV2 << transactionV2;
    const std::vector<unsigned char> originalV2(
        encodedV2.begin(), encodedV2.end());
    BOOST_REQUIRE(!encodedV2.empty());
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(encodedV2[0]), 2U);

    SpendTransaction decodedV2(
        params, SpendTransactionVersion::V2, out_coin_data.size());
    encodedV2 >> decodedV2;
    BOOST_CHECK(encodedV2.empty());
    CDataStream canonicalV2(SER_NETWORK, PROTOCOL_VERSION);
    canonicalV2 << decodedV2;
    BOOST_CHECK(std::equal(
        canonicalV2.begin(), canonicalV2.end(), originalV2.begin(),
        [](char left, unsigned char right) {
            return static_cast<unsigned char>(left) == right;
        }));
    decodedV2.setOutCoins(transactionV2.getOutCoins());
    decodedV2.setVout(0);
    decodedV2.setCoverSets(cover_set_data);
    BOOST_CHECK(SpendTransaction::verify(decodedV2, cover_sets));

    CDataStream reorderedIds(SER_NETWORK, PROTOCOL_VERSION);
    reorderedIds << transactionV2;
    // The first three bytes are the version and the two CompactSize counts;
    // fixed-width input identifiers follow immediately.
    BOOST_REQUIRE_GE(reorderedIds.size(), 19U);
    std::swap_ranges(
        reorderedIds.begin() + 3,
        reorderedIds.begin() + 11,
        reorderedIds.begin() + 11);
    SpendTransaction reorderedParser(
        params, SpendTransactionVersion::V2, out_coin_data.size());
    reorderedIds >> reorderedParser;
    BOOST_CHECK(reorderedIds.empty());
    reorderedParser.setOutCoins(transactionV2.getOutCoins());
    reorderedParser.setVout(0);
    reorderedParser.setCoverSets(cover_set_data);
    BOOST_CHECK(!SpendTransaction::verify(reorderedParser, cover_sets));

    SpendTransaction extraneousCoverSet(transactionV2);
    extraneousCoverSet.setBlockHashes({{999, uint256S("02")}});
    CDataStream extraneousEncoding(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_THROW(
        extraneousEncoding << extraneousCoverSet, std::exception);

    SpendTransaction missingCoverSet(transactionV2);
    missingCoverSet.setBlockHashes({});
    CDataStream missingEncoding(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_THROW(
        missingEncoding << missingCoverSet, std::exception);

    // Historical V1 has no inner version byte, so arbitrary V2 bytes are not
    // guaranteed to fail while being decoded as V1. Consensus selects the
    // parser from the transaction type and activation height.
    // spark_v2_activation_and_wallet_selection retags v2Multi as
    // TRANSACTION_SPARK and asserts CheckSparkTransaction rejects it.

    CDataStream truncatedV2(SER_NETWORK, PROTOCOL_VERSION);
    truncatedV2 << transactionV2;
    truncatedV2.resize(truncatedV2.size() - 1);
    SpendTransaction truncatedParser(
        params, SpendTransactionVersion::V2, out_coin_data.size());
    BOOST_CHECK_THROW(truncatedV2 >> truncatedParser, std::exception);

    CDataStream encodedV1(SER_NETWORK, PROTOCOL_VERSION);
    encodedV1 << transaction;
    SpendTransaction wrongV2Parser(
        params, SpendTransactionVersion::V2, out_coin_data.size());
    BOOST_CHECK_THROW(encodedV1 >> wrongV2Parser, std::exception);

    CDataStream wrongVersion(SER_NETWORK, PROTOCOL_VERSION);
    wrongVersion << transactionV2;
    wrongVersion[0] = 3;
    SpendTransaction rejectedVersion(
        params, SpendTransactionVersion::V2, out_coin_data.size());
    BOOST_CHECK_THROW(wrongVersion >> rejectedVersion, std::exception);

    CDataStream oversized(SER_NETWORK, PROTOCOL_VERSION);
    oversized.write("\x02\x65", 2); // V2, 101 inputs (limit is 100)
    SpendTransaction boundedParser(
        params, SpendTransactionVersion::V2, out_coin_data.size());
    BOOST_CHECK_THROW(oversized >> boundedParser, std::exception);
}

BOOST_AUTO_TEST_SUITE_END()

}
