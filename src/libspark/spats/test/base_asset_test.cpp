#include "../base_asset.h"
#include "../../streams.h"
#include "../../version.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spats {

BOOST_FIXTURE_TEST_SUITE(spats_base_asset_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(serialization)
{
    GroupElement G;
    G.randomize();

    GroupElement H;
    H.randomize();

    Scalar y;
    y.randomize();

    Scalar z;
    z.randomize();

    GroupElement C = G*y+H*z;

    BaseAssetProof proof;

    BaseAsset base(G,H);
    base.prove(y,z, C, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    BaseAssetProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.A == deserialized.A);
    BOOST_CHECK(proof.ty == deserialized.ty);
    BOOST_CHECK(proof.tz == deserialized.tz);
}

BOOST_AUTO_TEST_CASE(completeness)
{
    GroupElement G;
    G.randomize();

    GroupElement H;
    H.randomize();

    Scalar y;
    y.randomize();
    Scalar z;
    z.randomize();
    GroupElement C = G*y+H*z;

    BaseAssetProof proof;

    BaseAsset base(G,H);
    base.prove(y,z, C, proof);

    BOOST_CHECK(base.verify(C, proof));
}

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

    BaseAsset base(G,H);
    base.prove(y,z, C, proof);

    BOOST_CHECK(base.verify(C, proof));
}

BOOST_AUTO_TEST_CASE(bad_proofs)
{
    GroupElement G;
    G.randomize();

    GroupElement H;
    H.randomize();

    Scalar y;
    y.randomize();

    Scalar z;
    z.randomize();

    GroupElement C = G*y+H*z;

    BaseAssetProof proof;

    BaseAsset base(G,H);
    base.prove(y,z, C, proof);

    // Bad C
    GroupElement evil_C;
    evil_C.randomize();
    BOOST_CHECK(!(base.verify(evil_C, proof)));

    // Bad A
    BaseAssetProof evil_proof = proof;
    evil_proof.A.randomize();
    BOOST_CHECK(!(base.verify(C, evil_proof)));

    // Bad ty
    evil_proof = proof;
    evil_proof.ty.randomize();
    BOOST_CHECK(!(base.verify(C, evil_proof)));

    // Bad tz
    evil_proof = proof;
    evil_proof.tz.randomize();
    BOOST_CHECK(!(base.verify(C, evil_proof)));
}

BOOST_AUTO_TEST_SUITE_END()

}
