#include "../balance.h"
#include "../../../streams.h"
#include "../../../version.h"

#include "../../../test/test_bitcoin.h"
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

// Test with zero values
BOOST_AUTO_TEST_CASE(zero_values)
{
    GroupElement E;
    E.randomize();
    GroupElement F;
    F.randomize();
    GroupElement H;
    H.randomize();

    // All zeros except z (blinding factor)
    Scalar w = Scalar(uint64_t(0));
    Scalar x = Scalar(uint64_t(0));
    Scalar z;
    z.randomize();

    BalanceProof proof;
    GroupElement C = E*w + F*x + H*z;

    Balance bal(E, F, H);
    bal.prove(C, w, x, z, proof);

    BOOST_CHECK(bal.verify(C, proof));
}

// Test proof cannot be reused with different commitment
BOOST_AUTO_TEST_CASE(proof_not_reusable)
{
    GroupElement E;
    E.randomize();
    GroupElement F;
    F.randomize();
    GroupElement H;
    H.randomize();

    Scalar w1, x1, z1;
    w1.randomize();
    x1.randomize();
    z1.randomize();

    Scalar w2, x2, z2;
    w2.randomize();
    x2.randomize();
    z2.randomize();

    GroupElement C1 = E*w1 + F*x1 + H*z1;
    GroupElement C2 = E*w2 + F*x2 + H*z2;

    BalanceProof proof1;
    Balance bal(E, F, H);
    bal.prove(C1, w1, x1, z1, proof1);

    // Proof for C1 should verify for C1
    BOOST_CHECK(bal.verify(C1, proof1));

    // Proof for C1 should NOT verify for C2
    BOOST_CHECK(!bal.verify(C2, proof1));
}

// Test with different generators
BOOST_AUTO_TEST_CASE(different_generators)
{
    // Two different sets of generators
    GroupElement E1, F1, H1;
    E1.randomize();
    F1.randomize();
    H1.randomize();

    GroupElement E2, F2, H2;
    E2.randomize();
    F2.randomize();
    H2.randomize();

    Scalar w, x, z;
    w.randomize();
    x.randomize();
    z.randomize();

    GroupElement C1 = E1*w + F1*x + H1*z;

    BalanceProof proof;
    Balance bal1(E1, F1, H1);
    bal1.prove(C1, w, x, z, proof);

    // Should verify with correct generators
    BOOST_CHECK(bal1.verify(C1, proof));

    // Should NOT verify with different generators
    Balance bal2(E2, F2, H2);
    BOOST_CHECK(!bal2.verify(C1, proof));
}

// Test multiple sequential proofs
BOOST_AUTO_TEST_CASE(multiple_proofs)
{
    GroupElement E, F, H;
    E.randomize();
    F.randomize();
    H.randomize();

    Balance bal(E, F, H);

    for (int i = 0; i < 5; i++) {
        Scalar w, x, z;
        w.randomize();
        x.randomize();
        z.randomize();

        GroupElement C = E*w + F*x + H*z;

        BalanceProof proof;
        bal.prove(C, w, x, z, proof);

        BOOST_CHECK(bal.verify(C, proof));
    }
}

BOOST_AUTO_TEST_SUITE_END()

}
