#include "../schnorr_proof.h"
#include "../schnorr_prover.h"
#include "../schnorr_verifier.h"
#include "../../streams.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

class SchnorrProofTests {
public:
    SchnorrProofTests()
    {
        g.randomize();
        h.randomize();
        P.randomize();
        T.randomize();
        a.randomize();
        b.randomize();
    }

public:
    GroupElement g, h, a, b;
    Scalar P, T;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_schnorr_proof_tests, SchnorrProofTests)

BOOST_AUTO_TEST_CASE(serialization)
{
    SchnorrProver prover(g, h, true);
    GroupElement y;
    y.randomize();
    SchnorrProof proof;
    prover.proof(P, T, y, a, b, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    SchnorrProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.u == deserialized.u);
    BOOST_CHECK(proof.P1 == deserialized.P1);
    BOOST_CHECK(proof.T1 == deserialized.T1);
}

BOOST_AUTO_TEST_CASE(prove_verify)
{
    auto y = LelantusPrimitives::commit(g, P, h, T);

    SchnorrProver prover(g, h, true);
    SchnorrProof proof;
    prover.proof(P, T, y, a, b, proof);

    SchnorrVerifier verifier(g, h, true);
    BOOST_CHECK(verifier.verify(y, a, b, proof));
}

BOOST_AUTO_TEST_CASE(fake_prove_not_verify)
{
    auto y = LelantusPrimitives::commit(g, P, h, T);

    SchnorrProver prover(g, h, true);
    SchnorrProof proof;
    prover.proof(P, T, y, a, b, proof);

    GroupElement fakeY;
    fakeY.randomize();

    SchnorrVerifier verifier(g, h, true);
    BOOST_CHECK(!verifier.verify(fakeY, a, b, proof));

    auto fakeProof = proof;
    fakeProof.P1.randomize();
    BOOST_CHECK(!verifier.verify(y, a, b, fakeProof));

    fakeProof = proof;
    fakeProof.T1.randomize();
    BOOST_CHECK(!verifier.verify(y, a, b, fakeProof));

    fakeProof = proof;
    fakeProof.u.randomize();
    BOOST_CHECK(!verifier.verify(y, a, b, fakeProof));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus