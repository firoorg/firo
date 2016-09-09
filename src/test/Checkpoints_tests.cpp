//
// Unit tests for block-chain checkpoints
//
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "../checkpoints.h"
#include "../util.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
    uint256 p0 = uint256("0x093ee56cad4aa20fa8ddd21c987958bfd368c165643295f2e25a518fda2e0c3b");
    BOOST_CHECK(Checkpoints::CheckBlock(0, p0));

    // TODO: Update these after release when we have more checkpoints
    // Wrong hashes at checkpoints should fail:
    /*BOOST_CHECK(!Checkpoints::CheckBlock(1500, p120000));
    BOOST_CHECK(!Checkpoints::CheckBlock(120000, p1500));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckBlock(1500+1, p120000));
    BOOST_CHECK(Checkpoints::CheckBlock(120000+1, p1500));

    BOOST_CHECK(Checkpoints::GetTotalBlocksEstimate() >= 120000);*/
}    

BOOST_AUTO_TEST_SUITE_END()
