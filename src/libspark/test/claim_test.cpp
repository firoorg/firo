#include "../spend_transaction.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

// Transaction-level claim tests live in spend_transaction_test.cpp. This
// suite pins the claim binding itself: it commits to the identifier and
// message, and a proof under it is never a valid authorizing proof.
BOOST_FIXTURE_TEST_SUITE(spark_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(binding_separates_claims_from_authorizing_proofs)
{
    const Params* params = Params::get_test();
    Scalar mu;
    mu.randomize();
    const std::vector<unsigned char> identifier = {1, 2, 3};
    const std::vector<unsigned char> message = {4, 5, 6};

    const Scalar claim_mu = SpendTransaction::hash_bind_claim(mu, identifier, message);
    BOOST_CHECK(claim_mu == SpendTransaction::hash_bind_claim(mu, identifier, message));
    BOOST_CHECK(claim_mu != mu);
    BOOST_CHECK(claim_mu != SpendTransaction::hash_bind_claim(mu, {7, 2, 3}, message));
    BOOST_CHECK(claim_mu != SpendTransaction::hash_bind_claim(mu, identifier, {7, 5, 6}));

    Scalar x, y, z;
    x.randomize();
    y.randomize();
    z.randomize();
    const std::vector<GroupElement> S{params->get_F()*x + params->get_G()*y + params->get_H()*z};
    const std::vector<GroupElement> T{(params->get_U() + params->get_G()*y.negate())*x.inverse()};
    const ChaumV2Context context;
    Chaum chaum(params->get_F(), params->get_G(), params->get_H(), params->get_U());

    ChaumProofV2 claim, authorization;
    chaum.prove_v2(claim_mu, context, {x}, {y}, {z}, S, T, claim);
    chaum.prove_v2(mu, context, {x}, {y}, {z}, S, T, authorization);
    BOOST_CHECK(chaum.verify_v2(claim_mu, context, S, T, claim));
    BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, claim));
    BOOST_CHECK(!chaum.verify_v2(claim_mu, context, S, T, authorization));
}

BOOST_AUTO_TEST_SUITE_END()

}
