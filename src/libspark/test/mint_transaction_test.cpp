#include "../mint_transaction.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(spark_mint_transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(generate_verify)
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

    // Generate mint transaction
    MintTransaction t(
        params,
        address,
        v,
        memo
    );

    // Verify
    BOOST_CHECK(t.verify());
}

BOOST_AUTO_TEST_SUITE_END()

}
