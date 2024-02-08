#include "../balance.h"
#include "../../streams.h"
#include "../../version.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spats {

using namespace secp_primitives;

BOOST_FIXTURE_TEST_SUITE(spats_balance_proof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(serialization)
{
    GroupElement E;
    E.randomize();
    GroupElement F;
    F.randomize();
    GroupElement H;
    H.randomize();

    Scalar w;
    Scalar x;
    Scalar z;
    w.randomize();
    x.randomize();
    z.randomize();

    BalanceProof proof;
    GroupElement C = E*w+F*x+H*z;

    Balance bal(E,F,H);
    bal.prove(C, w,x,z, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    BalanceProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.A == deserialized.A);
    BOOST_CHECK(proof.tw == deserialized.tw);
    BOOST_CHECK(proof.tx == deserialized.tx);
    BOOST_CHECK(proof.tz == deserialized.tz);
}

BOOST_AUTO_TEST_CASE(completeness)
{
    GroupElement E;
    E.randomize();
    GroupElement F;
    F.randomize();
    GroupElement H;
    H.randomize();
    
    Scalar w;
    Scalar x;
    Scalar z;
    w.randomize();
    x.randomize();
    z.randomize();

    BalanceProof proof;
    GroupElement C = E*w+F*x+H*z;

    Balance bal(E,F,H);
    bal.prove(C,w,x,z,proof);

    // Verify
    BOOST_CHECK(bal.verify(C,proof));
}

BOOST_AUTO_TEST_CASE(bad_proofs)
{
    GroupElement E;
    E.randomize();
    GroupElement F;
    F.randomize();
    GroupElement H;
    H.randomize();

    Scalar w;
    Scalar x;
    Scalar z;
    w.randomize();
    x.randomize();
    z.randomize();

    BalanceProof proof;
    GroupElement C = E*w+F*x+H*z;

    Balance bal(E,F,H);
    bal.prove(C,w,x,z,proof);

    // Bad C
    GroupElement evil_C;
    evil_C.randomize();
    BOOST_CHECK(!(bal.verify(evil_C, proof)));

    // Bad A
    BalanceProof evil_proof = proof;
    evil_proof.A.randomize();
    BOOST_CHECK(!(bal.verify(C, evil_proof)));

    // Bad tw
    evil_proof = proof;
    evil_proof.tw.randomize();
    BOOST_CHECK(!(bal.verify(C, evil_proof)));
    // Bad tx
    evil_proof = proof;
    evil_proof.tx.randomize();
    BOOST_CHECK(!(bal.verify(C, evil_proof)));
    // Bad tz
    evil_proof = proof;
    evil_proof.tz.randomize();
    BOOST_CHECK(!(bal.verify(C, evil_proof)));
}

BOOST_AUTO_TEST_SUITE_END()

}
