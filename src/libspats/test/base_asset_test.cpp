#include "../base_asset.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spats {

using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(spats_base_asset_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(completeness_aggregate)
{
    const std::size_t n = 3;

    GroupElement G;
    G.randomize();
    GroupElement H;
    H.randomize();

    std::vector<Scalar> y;
    std::vector<Scalar> z;
	std::vector<GroupElement> C;

    for (std::size_t i = 0; i < n; i++) {
        y.emplace_back();
        y.back().randomize();
        z.emplace_back();
        z.back().randomize();

        C.emplace_back(G*y.back()+H*z.back());
    }

    BaseAssetProof proof;

    BaseAsset basea(G,H);
    basea.prove(y,z, C, proof);

    BOOST_CHECK(basea.verify(C, proof));
}

BOOST_AUTO_TEST_SUITE_END()

}
