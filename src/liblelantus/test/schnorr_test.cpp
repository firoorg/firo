#include "../schnorr_proof.h"
#include "../schnorr_prover.h"
#include "../schnorr_verifier.h"
#include "../../streams.h"
#include "../../version.h"


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
    }

public:
    GroupElement g, h;
    Scalar P, T;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_schnorr_proof_tests, SchnorrProofTests)

BOOST_AUTO_TEST_CASE(serialization)
{
    SchnorrProver prover(g, h);
    SchnorrProof proof;
    prover.proof(P, T, proof);

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

    SchnorrProver prover(g, h);
    SchnorrProof proof;
    prover.proof(P, T, proof);

    SchnorrVerifier verifier(g, h);
    BOOST_CHECK(verifier.verify(y ,proof));
}

BOOST_AUTO_TEST_CASE(fake_prove_not_verify)
{
    auto y = LelantusPrimitives::commit(g, P, h, T);

    SchnorrProver prover(g, h);
    SchnorrProof proof;
    prover.proof(P, T, proof);

    GroupElement fakeY;
    fakeY.randomize();

    SchnorrVerifier verifier(g, h);
    BOOST_CHECK(!verifier.verify(fakeY, proof));

    auto fakeProof = proof;
    fakeProof.P1.randomize();
    BOOST_CHECK(!verifier.verify(y, fakeProof));

    fakeProof = proof;
    fakeProof.T1.randomize();
    BOOST_CHECK(!verifier.verify(y, fakeProof));

    fakeProof = proof;
    fakeProof.u.randomize();
    BOOST_CHECK(!verifier.verify(y, fakeProof));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus