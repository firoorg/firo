#include "../schnorr_proof.h"
#include "../schnorr_prover.h"
#include "../schnorr_verifier.h"
#include "../challenge_generator_impl.h"
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
    unique_ptr<ChallengeGenerator> challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1);
    SchnorrProver prover(g, h, true);
    GroupElement y;
    y.randomize();
    SchnorrProof proof;
    prover.proof(P, T, y, a, b, challengeGenerator, proof);

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
    unique_ptr<ChallengeGenerator> challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1);

    SchnorrProver prover(g, h, true);
    SchnorrProof proof;
    prover.proof(P, T, y, a, b, challengeGenerator, proof);

    SchnorrVerifier verifier(g, h, true);
    challengeGenerator.reset(new ChallengeGeneratorImpl<CHash256>(1));
    BOOST_CHECK(verifier.verify(y, a, b, proof, challengeGenerator));
}

BOOST_AUTO_TEST_CASE(fake_prove_not_verify)
{
    auto y = LelantusPrimitives::commit(g, P, h, T);
    unique_ptr<ChallengeGenerator> challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1);

    SchnorrProver prover(g, h, true);
    SchnorrProof proof;
    prover.proof(P, T, y, a, b, challengeGenerator, proof);

    GroupElement fakeY;
    fakeY.randomize();

    SchnorrVerifier verifier(g, h, true);
    challengeGenerator.reset(new ChallengeGeneratorImpl<CHash256>(1));
    BOOST_CHECK(!verifier.verify(fakeY, a, b, proof, challengeGenerator));

    auto fakeProof = proof;
    fakeProof.P1.randomize();
    challengeGenerator.reset(new ChallengeGeneratorImpl<CHash256>(1));
    BOOST_CHECK(!verifier.verify(y, a, b, fakeProof, challengeGenerator));

    fakeProof = proof;
    fakeProof.T1.randomize();
    challengeGenerator.reset(new ChallengeGeneratorImpl<CHash256>(1));
    BOOST_CHECK(!verifier.verify(y, a, b, fakeProof, challengeGenerator));

    fakeProof = proof;
    fakeProof.u.randomize();
    challengeGenerator.reset(new ChallengeGeneratorImpl<CHash256>(1));
    BOOST_CHECK(!verifier.verify(y, a, b, fakeProof, challengeGenerator));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus