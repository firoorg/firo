#include "../keys.h"
#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_address_ownership_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(serialization)
{
    Scalar m;
    m.randomize();

    OwnershipProof proof;

    const Params* params;
    params = Params::get_test();

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    Address address(incoming_view_key, i);
    address.prove_own(m, spend_key, incoming_view_key, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    OwnershipProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.A == deserialized.A);
    BOOST_CHECK(proof.t1 == deserialized.t1);
    BOOST_CHECK(proof.t2 == deserialized.t2);
    BOOST_CHECK(proof.t3 == deserialized.t3);

}

BOOST_AUTO_TEST_CASE(completeness)
{
    Scalar m;
    m.randomize();

    OwnershipProof proof;

    const Params* params;
    params = Params::get_test();

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    Address address(incoming_view_key, i);
    address.prove_own(m, spend_key, incoming_view_key, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    OwnershipProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(address.verify_own(m, deserialized));
}

BOOST_AUTO_TEST_CASE(bad_proofs)
{
    Scalar m;
    m.randomize();

    OwnershipProof proof;

    const Params* params;
    params = Params::get_test();

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    const uint64_t i = 12345;
    Address address(incoming_view_key, i);
    address.prove_own(m, spend_key, incoming_view_key, proof);

    OwnershipProof evil_proof1 = proof;
    evil_proof1.A.randomize();
    BOOST_CHECK(!address.verify_own(m, evil_proof1));

    OwnershipProof evil_proof2 = proof;
    evil_proof2.t1.randomize();
    BOOST_CHECK(!address.verify_own(m, evil_proof2));

    OwnershipProof evil_proof3 = proof;
    evil_proof3.t2.randomize();
    BOOST_CHECK(!address.verify_own(m, evil_proof3));

    OwnershipProof evil_proof4 = proof;
    evil_proof4.t3.randomize();
    BOOST_CHECK(!address.verify_own(m, evil_proof4));
}

BOOST_AUTO_TEST_SUITE_END()

}
