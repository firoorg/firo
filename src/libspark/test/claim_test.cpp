#include "../spend_transaction.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

// Transaction-level claim tests live in spend_transaction_test.cpp. This
// suite pins the claim binding itself: it commits to the transaction binding
// hash, identifier and message, and a proof under it is never a valid
// authorizing proof.
BOOST_FIXTURE_TEST_SUITE(spark_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(binding_separates_claims_from_authorizing_proofs)
{
    const Scalar mu(uint64_t(42));
    const std::vector<unsigned char> identifier = {1, 2, 3};
    const std::vector<unsigned char> message = {4, 5, 6};

    // Claims travel between independently built wallets and verifiers, so the
    // CLAIM_V2 encoding is pinned to a vector computed outside this codebase.
    const Scalar claim_mu = SpendTransaction::hash_bind_claim(mu, identifier, message);
    BOOST_CHECK_EQUAL(claim_mu.GetHex(), "069eddb1bf3a3a0b3fed1f9584313a2a55dd04172aed7f8d0450f1ed39a94b2f");
    BOOST_CHECK(claim_mu != SpendTransaction::hash_bind_claim(mu + Scalar(uint64_t(1)), identifier, message));
    BOOST_CHECK(claim_mu != SpendTransaction::hash_bind_claim(mu, {7, 2, 3}, message));
    BOOST_CHECK(claim_mu != SpendTransaction::hash_bind_claim(mu, identifier, {7, 5, 6}));

    // Random generators, as in chaum_test.cpp: Params::get_test() would fix
    // test-sized parameters for every later suite in the same process.
    GroupElement F, G, H, U;
    F.randomize();
    G.randomize();
    H.randomize();
    U.randomize();
    Scalar x, y, z;
    x.randomize();
    y.randomize();
    z.randomize();
    const std::vector<GroupElement> S{F*x + G*y + H*z};
    const std::vector<GroupElement> T{(U + G*y.negate())*x.inverse()};
    const ChaumV2Context context;
    Chaum chaum(F, G, H, U);

    ChaumProofV2 claim, authorization;
    chaum.prove_v2(claim_mu, context, {x}, {y}, {z}, S, T, claim);
    chaum.prove_v2(mu, context, {x}, {y}, {z}, S, T, authorization);
    BOOST_CHECK(chaum.verify_v2(claim_mu, context, S, T, claim));
    BOOST_CHECK(!chaum.verify_v2(mu, context, S, T, claim));
    BOOST_CHECK(!chaum.verify_v2(claim_mu, context, S, T, authorization));
}

BOOST_AUTO_TEST_SUITE_END()

}
