#include "../innerproduct_proof_generator.h"
#include "../innerproduct_proof_verifier.h"

#include "./lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

class InnerProductTests : public LelantusTestingSetup {
public:
    typedef InnerProductProofGenerator ProofGenerator;
    typedef InnerProductProofVerifier ProofVerifier;
    typedef InnerProductProof Proof;

public:
    InnerProductTests() {}

public:
    void Generate(size_t n) {
        gens_g = RandomizeGroupElements(n);
        gens_h = RandomizeGroupElements(n);
        a = RandomizeScalars(n);
        b = RandomizeScalars(n);
        u.randomize();
    }

    Scalar ComputeC() const {
        return Primitives::scalar_dot_product(a.begin(), a.end(), b.begin(), b.end());
    }

    GroupElement ComputePInit() const {
        return ComputeMultiExponent(gens_g, a) + ComputeMultiExponent(gens_h, b);
    }

    GroupElement ComputeP(Scalar const &x) const {
        return ComputePInit() + u * ComputeC() * x;
    }

public:
    std::vector<GroupElement> gens_g;
    std::vector<GroupElement> gens_h;
    std::vector<Scalar> a;
    std::vector<Scalar> b;
    GroupElement u;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_inner_product_tests, InnerProductTests)

BOOST_AUTO_TEST_CASE(prove_verify_one)
{
    size_t n = 1;
    size_t log2_n = 0;

    Generate(n);

    Scalar x;
    x.randomize();
    ChallengeGeneratorSha256 challengeGenerator;

    // generating proofs
    Proof proof;
    ProofGenerator prover(gens_g, gens_h, u);
    prover.generate_proof(a, b, x, &challengeGenerator, proof);

    BOOST_CHECK_EQUAL(ComputePInit(), prover.get_P());

    // validate
    BOOST_CHECK_EQUAL(ComputeC(), proof.c_);
    BOOST_CHECK_EQUAL(a.front(), proof.a_);
    BOOST_CHECK_EQUAL(b.front(), proof.b_);
    BOOST_CHECK_EQUAL(log2_n, proof.L_.size());
    BOOST_CHECK_EQUAL(log2_n, proof.R_.size());

    // verify
    BOOST_CHECK(ProofVerifier(gens_g, gens_h, u, ComputePInit()).verify(x, proof, &challengeGenerator));
    BOOST_CHECK(ProofVerifier(gens_g, gens_h, u, ComputePInit()).verify_fast(n, x, proof, &challengeGenerator));
}

BOOST_AUTO_TEST_CASE(prove_verify)
{
    size_t n = 32;
    size_t log2_n = 5;

    Generate(n);

    Scalar x;
    x.randomize();
    ChallengeGeneratorSha256 challengeGenerator;

    // generating proofs
    Proof proof;
    ProofGenerator prover(gens_g, gens_h, u);
    prover.generate_proof(a, b, x, &challengeGenerator, proof);

    BOOST_CHECK_EQUAL(ComputePInit(), prover.get_P());

    // validate
    BOOST_CHECK_EQUAL(ComputeC(), proof.c_);
    BOOST_CHECK_EQUAL(log2_n, proof.L_.size());
    BOOST_CHECK_EQUAL(log2_n, proof.R_.size());

    // verify
    BOOST_CHECK(ProofVerifier(gens_g, gens_h, u, ComputePInit()).verify(x, proof, &challengeGenerator));
    BOOST_CHECK(ProofVerifier(gens_g, gens_h, u, ComputePInit()).verify_fast(n, x, proof, &challengeGenerator));
}

BOOST_AUTO_TEST_CASE(fake_proof_not_verify)
{
    size_t n = 32;

    // generating needed objects
    Generate(n);

    Scalar x;
    x.randomize();
    ChallengeGeneratorSha256 challengeGenerator;

    // generating genertor
    Proof proof;
    ProofGenerator(gens_g, gens_h, u).generate_proof(a, b, x, &challengeGenerator, proof);

    // verify with fake P
    GroupElement fakeP;
    fakeP.randomize();

    BOOST_CHECK(!ProofVerifier(gens_g, gens_h, u, fakeP).verify(x, proof, &challengeGenerator));
    BOOST_CHECK(!ProofVerifier(gens_g, gens_h, u, fakeP).verify_fast(n, x, proof, &challengeGenerator));

    // verify with fake proof
    auto verify = [&](Scalar const &_x, Proof const &_p) -> void {
        BOOST_CHECK(!ProofVerifier(gens_g, gens_h, u, ComputePInit()).verify(_x, _p, &challengeGenerator));
        BOOST_CHECK(!ProofVerifier(gens_g, gens_h, u, ComputePInit()).verify_fast(n, _x, _p, &challengeGenerator));
    };

    auto fakeProof = proof;
    fakeProof.a_.randomize();
    verify(x, fakeProof);

    fakeProof = proof;
    fakeProof.b_.randomize();
    verify(x, fakeProof);

    fakeProof = proof;
    fakeProof.c_.randomize();
    verify(x, fakeProof);

    fakeProof = proof;
    fakeProof.L_[0].randomize();
    verify(x, fakeProof);

    fakeProof = proof;
    fakeProof.R_[0].randomize();
    verify(x, fakeProof);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus