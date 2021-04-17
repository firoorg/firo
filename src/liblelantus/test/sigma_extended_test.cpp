#include "../sigmaextended_prover.h"
#include "../sigmaextended_verifier.h"

#include "lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

class SigmaExtendedTests : public LelantusTestingSetup {
public:
    struct Secret {
    public:
        Secret(int l) : l(l) {
            s.randomize();
            v.randomize();
            r.randomize();
        }

    public:
        int l;
        Scalar s, v, r;
    };

public:
    typedef SigmaExtendedProver Prover;
    typedef SigmaExtendedProof Proof;
    typedef SigmaExtendedVerifier Verifier;

public:
    SigmaExtendedTests() {}

public:
    void GenerateParams(int _N, int _n, int _m = 0) {
        N = _N;
        n = _n;
        m = _m;
        if (!m) {
            if (n <= 1) {
                throw std::logic_error("Try to get value of m from invalid n");
            }

            m = std::round(log(N) / log(n));
        }

        h_gens = RandomizeGroupElements(n * m);
        g.randomize();
    }

    void GenerateBatchProof(
        Prover &prover,
        std::vector<GroupElement> const &coins,
        int l,
        Scalar const &s,
        Scalar const &v,
        Scalar const &r,
        Scalar const &x,
        Proof &proof
    ) {
        auto gs = g * s.negate();
        std::vector<GroupElement> commits(coins.begin(), coins.end());
        for (auto &c : commits) {
            c += gs;
        }

        Scalar rA, rB, rC, rD;
        rA.randomize();
        rB.randomize();
        rC.randomize();
        rD.randomize();

        std::vector<Scalar> sigma;
        std::vector<Scalar> Tk, Pk, Yk;
        Tk.resize(m);
        Pk.resize(m);
        Yk.resize(m);

        std::vector<Scalar> a;
        a.resize(n * m);

        prover.sigma_commit(
            commits, l, rA, rB, rC, rD, a, Tk, Pk, Yk, sigma, proof);

        prover.sigma_response(
            sigma, a, rA, rB, rC, rD, v, r, Tk, Pk, x, proof);
    }

public:
    int N;
    int n;
    int m;

    std::vector<GroupElement> h_gens;
    GroupElement g;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_sigma_tests, SigmaExtendedTests)

BOOST_AUTO_TEST_CASE(one_out_of_N_batch)
{
    GenerateParams(16, 4);

    auto commits = RandomizeGroupElements(N);

    // Generate
    std::vector<Secret> secrets;

    for (auto index : {1, 3, 5, 9, 15}) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits[index] = Primitives::double_commit(
            g, s.s, h_gens[1], s.v, h_gens[0], s.r);
    }

    Prover prover(g, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;

    Scalar x;
    x.randomize();

    for (auto const &s : secrets) {
        proofs.emplace_back();
        serials.push_back(s.s);
        GenerateBatchProof(
            prover, commits, s.l, s.s, s.v, s.r, x, proofs.back());
    }

    Verifier verifier(g, h_gens, n, m);
    BOOST_CHECK(verifier.batchverify(commits, x, serials, proofs));

    // verify subset of valid proofs should success also
    serials.pop_back();
    proofs.pop_back();
    BOOST_CHECK(verifier.batchverify(commits, x, serials, proofs));
}

BOOST_AUTO_TEST_CASE(one_out_of_N_batch_with_some_invalid_proof)
{
    GenerateParams(16, 4);

    auto commits = RandomizeGroupElements(N);

    // Generate
    std::vector<Secret> secrets;

    for (auto index : {1, 3}) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits[index] = Primitives::double_commit(
            g, s.s, h_gens[1], s.v, h_gens[0], s.r);
    }

    Prover prover(g, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;

    Scalar x;
    x.randomize();

    for (auto const &s : secrets) {
        proofs.emplace_back();
        serials.push_back(s.s);
        GenerateBatchProof(
            prover, commits, s.l, s.s, s.v, s.r, x, proofs.back());
    }

    // Add an invalid
    proofs.push_back(proofs.back());

    serials.emplace_back(serials.back());
    serials.back().randomize();

    Verifier verifier(g, h_gens, n, m);
    BOOST_CHECK(!verifier.batchverify(commits, x, serials, proofs));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus