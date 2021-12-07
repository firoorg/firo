#include "../bpplus.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_bpplus_tests, BasicTestingSetup)

// Generate and verify a single aggregated proof
BOOST_AUTO_TEST_CASE(completeness_single)
{
    // Parameters
    std::size_t N = 64; // bit length
    std::size_t M = 4; // aggregation

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    Gi.resize(N*M);
    Hi.resize(N*M);
    for (std::size_t i = 0; i < N*M; i++) {
        Gi[i].randomize();
        Hi[i].randomize();
    }

    // Commitments
    std::vector<Scalar> v, r;
    v.resize(M);
    v[0] = Scalar(uint64_t(0));
    v[1] = Scalar(uint64_t(1));
    v[2] = Scalar(uint64_t(2));
    v[3] = Scalar(std::numeric_limits<uint64_t>::max());
    r.resize(M);
    std::vector<GroupElement> C;
    C.resize(M);
    for (std::size_t j = 0; j < M; j++) {
        r[j].randomize();
        C[j] = G*v[j] + H*r[j];
    }

    BPPlus bpplus(G, H, Gi, Hi, N);
    BPPlusProof proof;
    bpplus.prove(v, r, C, proof);

    BOOST_CHECK(bpplus.verify(C, proof));
}

// A single proof with invalid value
BOOST_AUTO_TEST_CASE(invalid_single)
{
    // Parameters
    std::size_t N = 64; // bit length
    std::size_t M = 4; // aggregation

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    Gi.resize(N*M);
    Hi.resize(N*M);
    for (std::size_t i = 0; i < N*M; i++) {
        Gi[i].randomize();
        Hi[i].randomize();
    }

    // Commitments
    std::vector<Scalar> v, r;
    v.resize(M);
    v[0] = Scalar(uint64_t(0));
    v[1] = Scalar(uint64_t(1));
    v[2] = Scalar(uint64_t(2));
    v[3] = Scalar(std::numeric_limits<uint64_t>::max()) + Scalar(uint64_t(1)); // out of range
    r.resize(M);
    std::vector<GroupElement> C;
    C.resize(M);
    for (std::size_t j = 0; j < M; j++) {
        r[j].randomize();
        C[j] = G*v[j] + H*r[j];
    }

    BPPlus bpplus(G, H, Gi, Hi, N);
    BPPlusProof proof;
    bpplus.prove(v, r, C, proof);

    BOOST_CHECK(!bpplus.verify(C, proof));
}

// Generate and verify a batch of proofs with variable aggregation
BOOST_AUTO_TEST_CASE(completeness_batch)
{
    // Parameters
    std::size_t N = 64; // bit length
    std::size_t B = 4; // number of proofs in batch

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    Gi.resize(N*(1 << B));
    Hi.resize(N*(1 << B));
    for (std::size_t i = 0; i < N*(1 << B); i++) {
        Gi[i].randomize();
        Hi[i].randomize();
    }

    BPPlus bpplus(G, H, Gi, Hi, N);
    std::vector<BPPlusProof> proofs;
    proofs.resize(B);
    std::vector<std::vector<GroupElement>> C;

    // Build each proof
    for (std::size_t i = 0; i < B; i++) {
        // Commitments
        std::size_t M = 1 << i;
        std::vector<Scalar> v, r;
        v.resize(M);
        r.resize(M);
        std::vector<GroupElement> C_;
        C_.resize(M);
        for (std::size_t j = 0; j < M; j++) {
            v[j] = Scalar(uint64_t(j));
            r[j].randomize();
            C_[j] = G*v[j] + H*r[j];
        }
        C.emplace_back(C_);

        bpplus.prove(v, r, C_, proofs[i]);
    }

    BOOST_CHECK(bpplus.verify(C, proofs));
}

// An invalid batch of proofs
BOOST_AUTO_TEST_CASE(invalid_batch)
{
    // Parameters
    std::size_t N = 64; // bit length
    std::size_t B = 4; // number of proofs in batch

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    Gi.resize(N*(1 << B));
    Hi.resize(N*(1 << B));
    for (std::size_t i = 0; i < N*(1 << B); i++) {
        Gi[i].randomize();
        Hi[i].randomize();
    }

    BPPlus bpplus(G, H, Gi, Hi, N);
    std::vector<BPPlusProof> proofs;
    proofs.resize(B);
    std::vector<std::vector<GroupElement>> C;

    // Build each proof
    for (std::size_t i = 0; i < B; i++) {
        // Commitments
        std::size_t M = 1 << i;
        std::vector<Scalar> v, r;
        v.resize(M);
        r.resize(M);
        std::vector<GroupElement> C_;
        C_.resize(M);
        for (std::size_t j = 0; j < M; j++) {
            v[j] = Scalar(uint64_t(j));
            // Set one proof to an out-of-range value;
            if (i == 0 && j == 0) {
                v[j] = Scalar(std::numeric_limits<uint64_t>::max()) + Scalar(uint64_t(1));
            }
            r[j].randomize();
            C_[j] = G*v[j] + H*r[j];
        }
        C.emplace_back(C_);

        bpplus.prove(v, r, C_, proofs[i]);
    }

    BOOST_CHECK(!bpplus.verify(C, proofs));
}

BOOST_AUTO_TEST_SUITE_END()

}
