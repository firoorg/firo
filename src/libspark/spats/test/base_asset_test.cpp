#include "../base_asset.h"
#include "../../../streams.h"
#include "../../../version.h"

#include "../../../test/test_bitcoin.h"
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

// Test with zero value
BOOST_AUTO_TEST_CASE(zero_value)
{
    GroupElement G, H;
    G.randomize();
    H.randomize();

    Scalar y = Scalar(uint64_t(0)); // zero value
    Scalar z;
    z.randomize();

    GroupElement C = G * y + H * z;

    BaseAssetProof proof;
    BaseAsset base(G, H);
    base.prove(y, z, C, proof);

    BOOST_CHECK(base.verify(C, proof));
}

// Test large aggregation
BOOST_AUTO_TEST_CASE(large_aggregate)
{
    const std::size_t n = 10;

    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<Scalar> y;
    std::vector<Scalar> z;
    std::vector<GroupElement> C;

    for (std::size_t i = 0; i < n; i++) {
        y.emplace_back();
        y.back().randomize();
        z.emplace_back();
        z.back().randomize();
        C.emplace_back(G * y.back() + H * z.back());
    }

    BaseAssetProof proof;
    BaseAsset base(G, H);
    base.prove(y, z, C, proof);

    BOOST_CHECK(base.verify(C, proof));
}

// Test proof cannot verify with different generators
BOOST_AUTO_TEST_CASE(different_generators_fail)
{
    GroupElement G1, H1;
    G1.randomize();
    H1.randomize();

    GroupElement G2, H2;
    G2.randomize();
    H2.randomize();

    Scalar y, z;
    y.randomize();
    z.randomize();

    GroupElement C = G1 * y + H1 * z;

    BaseAssetProof proof;
    BaseAsset base1(G1, H1);
    base1.prove(y, z, C, proof);

    // Should verify with correct generators
    BOOST_CHECK(base1.verify(C, proof));

    // Should NOT verify with different generators
    BaseAsset base2(G2, H2);
    BOOST_CHECK(!base2.verify(C, proof));
}

// Test non-base asset commitment fails (soundness)
BOOST_AUTO_TEST_CASE(non_base_asset_fails)
{
    GroupElement G, H;
    G.randomize();
    H.randomize();

    // Additional generator for non-base asset
    GroupElement E;
    E.randomize();

    Scalar y, z;
    y.randomize();
    z.randomize();

    // Valid base asset commitment (only G and H)
    GroupElement C_base = G * y + H * z;

    // Invalid commitment that includes E (non-base asset type)
    Scalar w;
    w.randomize();
    GroupElement C_non_base = E * w + G * y + H * z;

    BaseAssetProof proof;
    BaseAsset base(G, H);
    base.prove(y, z, C_base, proof);

    // Proof for base asset should verify
    BOOST_CHECK(base.verify(C_base, proof));

    // Proof should NOT verify for non-base commitment
    BOOST_CHECK(!base.verify(C_non_base, proof));
}

// Test single element vector
BOOST_AUTO_TEST_CASE(single_element_vector)
{
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<Scalar> y(1);
    std::vector<Scalar> z(1);
    y[0].randomize();
    z[0].randomize();

    std::vector<GroupElement> C(1);
    C[0] = G * y[0] + H * z[0];

    BaseAssetProof proof;
    BaseAsset base(G, H);
    base.prove(y, z, C, proof);

    BOOST_CHECK(base.verify(C, proof));
}

// Test deserialized proof still verifies
BOOST_AUTO_TEST_CASE(deserialized_proof_verifies)
{
    GroupElement G, H;
    G.randomize();
    H.randomize();

    Scalar y, z;
    y.randomize();
    z.randomize();

    GroupElement C = G * y + H * z;

    BaseAssetProof proof;
    BaseAsset base(G, H);
    base.prove(y, z, C, proof);

    // Serialize and deserialize
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << proof;

    BaseAssetProof deserialized;
    stream >> deserialized;

    // Deserialized proof should still verify
    BOOST_CHECK(base.verify(C, deserialized));
}

BOOST_AUTO_TEST_SUITE_END()

}
