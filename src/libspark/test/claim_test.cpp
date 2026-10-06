#include "../claim.h"
#include "../../streams.h"
#include "../../version.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {
namespace {

struct ClaimTestData {
    const Params* params = Params::get_test();
    Claim claim{params->get_F(), params->get_G(), params->get_H(), params->get_U()};
    Scalar mu{42};
    ChaumV2Context context;
    std::vector<unsigned char> identifier{0x01, 0x02};
    std::vector<unsigned char> message{0x03, 0x04};
    std::vector<Scalar> x, y, z;
    std::vector<GroupElement> S, T;

    explicit ClaimTestData(const std::size_t n) : x(n), y(n), z(n), S(n), T(n)
    {
        context.fee = 11;
        context.transparent_value = 22;
        context.serialized_outputs = {{0xaa}, {0xbb}};
        context.extension_commitment = uint256S("01");
        context.serialized_cover_set_references = {0x01, 0xaa};

        for (std::size_t i = 0; i < n; ++i) {
            x[i] = Scalar(i + 1);
            y[i] = Scalar(i + 2);
            z[i] = Scalar(i + 3);
            S[i] = params->get_F()*x[i] + params->get_G()*y[i] + params->get_H()*z[i];
            T[i] = (params->get_U() + params->get_G()*y[i].negate())*x[i].inverse();
        }
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(spark_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(completeness_serialization_and_output_reuse)
{
    ChaumProofV2 proof;
    for (const std::size_t n : {std::size_t{1}, std::size_t{3}, MAX_CHAUM_V2_INPUTS, std::size_t{1}}) {
        BOOST_TEST_CONTEXT("input count " << n) {
            ClaimTestData data(n);
            for (int generation = 0; generation < 2; ++generation) {
                data.message.back() ^= 1;
                data.claim.prove(
                    data.mu, data.context, data.identifier, data.message,
                    data.x, data.y, data.z, data.S, data.T, proof);
                BOOST_REQUIRE(data.claim.verify(
                    data.mu, data.context, data.identifier, data.message,
                    data.S, data.T, proof));

                CDataStream encoded(SER_NETWORK, PROTOCOL_VERSION);
                encoded << proof;
                ChaumProofV2 decoded;
                encoded >> decoded;
                BOOST_CHECK(data.claim.verify(
                    data.mu, data.context, data.identifier, data.message,
                    data.S, data.T, decoded));
                BOOST_CHECK(encoded.empty());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(binds_message_identifier_transaction_context_and_domain)
{
    ClaimTestData data(3);
    ChaumProofV2 proof;
    data.claim.prove(
        data.mu, data.context, data.identifier, data.message,
        data.x, data.y, data.z, data.S, data.T, proof);
    BOOST_REQUIRE(data.claim.verify(
        data.mu, data.context, data.identifier, data.message,
        data.S, data.T, proof));

    auto changed_identifier = data.identifier;
    changed_identifier.back() ^= 1;
    BOOST_CHECK(!data.claim.verify(
        data.mu, data.context, changed_identifier, data.message,
        data.S, data.T, proof));
    auto changed_message = data.message;
    changed_message.back() ^= 1;
    BOOST_CHECK(!data.claim.verify(
        data.mu, data.context, data.identifier, changed_message,
        data.S, data.T, proof));
    BOOST_CHECK(!data.claim.verify(
        data.mu + Scalar(1), data.context, data.identifier, data.message,
        data.S, data.T, proof));

    std::vector<ChaumV2Context> changed_contexts(5, data.context);
    ++changed_contexts[0].fee;
    ++changed_contexts[1].transparent_value;
    changed_contexts[2].serialized_outputs[0][0] ^= 1;
    changed_contexts[3].extension_commitment = uint256S("02");
    changed_contexts[4].serialized_cover_set_references.back() ^= 1;
    for (const auto& context : changed_contexts) {
        BOOST_CHECK(!data.claim.verify(
            data.mu, context, data.identifier, data.message,
            data.S, data.T, proof));
    }

    Chaum authorization(
        data.params->get_F(), data.params->get_G(),
        data.params->get_H(), data.params->get_U());
    BOOST_CHECK(!authorization.verify_v2(data.mu, data.context, data.S, data.T, proof));
    ChaumProofV2 authorization_proof;
    authorization.prove_v2(
        data.mu, data.context, data.x, data.y, data.z,
        data.S, data.T, authorization_proof);
    BOOST_REQUIRE(authorization.verify_v2(
        data.mu, data.context, data.S, data.T, authorization_proof));
    BOOST_CHECK(!data.claim.verify(
        data.mu, data.context, data.identifier, data.message,
        data.S, data.T, authorization_proof));
}

BOOST_AUTO_TEST_CASE(rejects_invalid_dimensions)
{
    ClaimTestData data(3);
    ChaumProofV2 proof;
    BOOST_CHECK_THROW(data.claim.prove(
        data.mu, data.context, data.identifier, data.message,
        {}, {}, {}, {}, {}, proof), std::invalid_argument);
    BOOST_CHECK(!data.claim.verify(
        data.mu, data.context, data.identifier, data.message, {}, {}, proof));
    BOOST_CHECK(!data.claim.verify(
        data.mu, data.context, data.identifier, data.message,
        data.S, data.T, proof));

    ClaimTestData oversized(MAX_CHAUM_V2_INPUTS + 1);
    BOOST_CHECK_THROW(oversized.claim.prove(
        oversized.mu, oversized.context, oversized.identifier, oversized.message,
        oversized.x, oversized.y, oversized.z, oversized.S, oversized.T, proof),
        std::invalid_argument);

    auto short_y = data.y;
    short_y.pop_back();
    BOOST_CHECK_THROW(data.claim.prove(
        data.mu, data.context, data.identifier, data.message,
        data.x, short_y, data.z, data.S, data.T, proof), std::invalid_argument);

    data.claim.prove(
        data.mu, data.context, data.identifier, data.message,
        data.x, data.y, data.z, data.S, data.T, proof);
    BOOST_REQUIRE(data.claim.verify(
        data.mu, data.context, data.identifier, data.message,
        data.S, data.T, proof));

    auto short_S = data.S;
    short_S.pop_back();
    BOOST_CHECK(!data.claim.verify(
        data.mu, data.context, data.identifier, data.message,
        short_S, data.T, proof));
    auto short_T = data.T;
    short_T.pop_back();
    BOOST_CHECK(!data.claim.verify(
        data.mu, data.context, data.identifier, data.message,
        data.S, short_T, proof));

    for (const auto member : {&ChaumProofV2::A1, &ChaumProofV2::A2}) {
        auto malformed = proof;
        (malformed.*member).pop_back();
        BOOST_CHECK(!data.claim.verify(
            data.mu, data.context, data.identifier, data.message,
            data.S, data.T, malformed));
        malformed = proof;
        (malformed.*member).emplace_back();
        BOOST_CHECK(!data.claim.verify(
            data.mu, data.context, data.identifier, data.message,
            data.S, data.T, malformed));
    }
    for (const auto member : {&ChaumProofV2::t1, &ChaumProofV2::t2, &ChaumProofV2::t3}) {
        auto malformed = proof;
        (malformed.*member).pop_back();
        BOOST_CHECK(!data.claim.verify(
            data.mu, data.context, data.identifier, data.message,
            data.S, data.T, malformed));
        malformed = proof;
        (malformed.*member).emplace_back();
        BOOST_CHECK(!data.claim.verify(
            data.mu, data.context, data.identifier, data.message,
            data.S, data.T, malformed));
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace spark
