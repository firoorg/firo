#include "../spats/nft_holding.h"
#include "../coin.h"
#include "../keys.h"
#include "../util.h"
#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_nft_holding_tests, BasicTestingSetup)

static NftHoldingProof Hold(const Params* params, const std::vector<unsigned char>& message, uint64_t value)
{
    const SpendKey spend_key(params);
    const FullViewKey full_view_key(spend_key);
    const IncomingViewKey incoming_view_key(full_view_key);
    const uint64_t diversifier = 7;
    const Address address(incoming_view_key, diversifier);
    Scalar k;
    k.randomize();
    const std::vector<unsigned char> serial_context(SCALAR_ENCODING, 9);
    const Scalar asset(uint64_t(3));
    const Scalar identifier(uint64_t(4));
    const Coin coin(params, COIN_TYPE_MINT_V2, k, address, value, "nft", serial_context, asset, identifier);
    const Scalar serial = SparkUtils::hash_ser(k, serial_context) +
        SparkUtils::hash_Q2(spend_key.get_s1(), Scalar(diversifier)) +
        spend_key.get_s2();
    const GroupElement tag = (params->get_U() + full_view_key.get_D().inverse()) * serial.inverse();
    return ProveNftHolding(
        params,
        coin.S,
        coin.C,
        tag,
        asset,
        identifier,
        serial,
        spend_key.get_r(),
        SparkUtils::hash_val(k),
        message);
}

BOOST_AUTO_TEST_CASE(holding_proof_accepts_the_message_it_was_bound_to)
{
    const Params* params = Params::get_test();
    const std::vector<unsigned char> message = {'h', 'o', 'l', 'd'};
    const NftHoldingProof proof = Hold(params, message, 1);
    BOOST_CHECK(VerifyNftHolding(params, proof, message));
}

BOOST_AUTO_TEST_CASE(holding_proof_rejects_a_different_message_or_identifier)
{
    const Params* params = Params::get_test();
    const std::vector<unsigned char> message = {'h', 'o', 'l', 'd'};
    NftHoldingProof proof = Hold(params, message, 1);
    BOOST_CHECK(!VerifyNftHolding(params, proof, {'o', 't', 'h', 'e', 'r'}));

    proof.iota = Scalar(uint64_t(5));
    BOOST_CHECK(!VerifyNftHolding(params, proof, message));
}

BOOST_AUTO_TEST_CASE(holding_proof_rejects_a_coin_whose_value_is_not_one)
{
    const Params* params = Params::get_test();
    BOOST_CHECK_THROW(Hold(params, {'h'}, 2), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

}
