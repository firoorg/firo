#include "../balance.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spats {

using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(spats_balance_proof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(verify_proof)
{
    // Parameters
    const Params* params;
    params = Params::get_default();
    
    Balance bal(params->get_E(),params->get_F(),params->get_H());
    Scalar w;
    Scalar x;
    Scalar z;
    w.randomize();
    x.randomize();
    z.randomize();

    BalanceProof bp = BalanceProof();

    bal.prove(params->get_E()*w+params->get_F()*x+params->get_H()*z,w,x,z,bp);

    // Verify
    BOOST_CHECK(bal.verify(params->get_E()*w+params->get_F()*x+params->get_H()*z,bp));
}

BOOST_AUTO_TEST_SUITE_END()

}
