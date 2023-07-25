#include "../mint_transaction.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

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

BOOST_FIXTURE_TEST_SUITE(spark_mint_transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(generate_verify)
{
    // Parameters
    const Params* params;
    params = Params::get_default();
    const std::size_t t = 3; // number of coins to generate
    
    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    std::vector<MintedCoinData> outputs;

    // Generate addresses and coins
    for (std::size_t j = 0; j < t; j++) {
        MintedCoinData output;
        output.address = Address(incoming_view_key, 12345 + j);
        output.v = 678 + j;
        output.memo = "Spam and eggs";

        outputs.emplace_back(output);
    }

    // Generate mint transaction
    MintTransaction mint(
        params,
        outputs,
        random_char_vector()
    );

    // Verify
    BOOST_CHECK(mint.verify());
}

BOOST_AUTO_TEST_SUITE_END()

}
