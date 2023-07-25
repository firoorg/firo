#include "../bpplus.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_bpplus_tests, BasicTestingSetup)

// Generate and verify a single aggregated proof with no padding
BOOST_AUTO_TEST_CASE(completeness_single_unpadded)
{
    // Parameters
    std::size_t N = 64; // bit length
    std::size_t M = 4; // aggregation

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    std::size_t gens_needed = N*M;
    if (!is_nonzero_power_of_2(gens_needed)) {
        gens_needed = 1 << (log2(N*M) + 1);
    }
    BOOST_CHECK_EQUAL(gens_needed, N*M);
    Gi.resize(gens_needed);
    Hi.resize(gens_needed);
    for (std::size_t i = 0; i < gens_needed; i++) {
        Gi[i].randomize();
        Hi[i].randomize();
    }

    // Commitments
    std::vector<Scalar> v, r;
    v.resize(M);
    v[0] = Scalar(uint64_t(0));
    v[1] = Scalar(uint64_t(1));
    v[2] = Scalar(uint64_t(2));
    v[3] = Scalar(uint64_t(3));
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

// Generate and verify a single aggregated proof with padding
BOOST_AUTO_TEST_CASE(completeness_single_padded)
{
    // Parameters
    std::size_t N = 64; // bit length
    std::size_t M = 5; // aggregation

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    std::size_t gens_needed = N*M;
    if (!is_nonzero_power_of_2(gens_needed)) {
        gens_needed = 1 << (log2(N*M) + 1);
    }
    BOOST_CHECK_EQUAL(gens_needed, 8*N); // hardcoded for this test
    Gi.resize(gens_needed);
    Hi.resize(gens_needed);
    for (std::size_t i = 0; i < gens_needed; i++) {
        Gi[i].randomize();
        Hi[i].randomize();
    }

    // Commitments
    std::vector<Scalar> v, r;
    v.resize(M);
    v[0] = Scalar(uint64_t(0));
    v[1] = Scalar(uint64_t(1));
    v[2] = Scalar(uint64_t(2));
    v[3] = Scalar(uint64_t(3));
    v[4] = Scalar(std::numeric_limits<uint64_t>::max());
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

// A single proof with invalid value and no padding
BOOST_AUTO_TEST_CASE(invalid_single_unpadded)
{
    // Parameters
    std::size_t N = 64; // bit length
    std::size_t M = 4; // aggregation

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    std::size_t gens_needed = N*M;
    if (!is_nonzero_power_of_2(gens_needed)) {
        gens_needed = 1 << (log2(N*M) + 1);
    }
    BOOST_CHECK_EQUAL(gens_needed, N*M);
    Gi.resize(gens_needed);
    Hi.resize(gens_needed);
    for (std::size_t i = 0; i < gens_needed; i++) {
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

// A single proof with invalid value and padding
BOOST_AUTO_TEST_CASE(invalid_single_padded)
{
    // Parameters
    std::size_t N = 64; // bit length
    std::size_t M = 5; // aggregation

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    std::size_t gens_needed = N*M;
    if (!is_nonzero_power_of_2(gens_needed)) {
        gens_needed = 1 << (log2(N*M) + 1);
    }
    BOOST_CHECK_EQUAL(gens_needed, 8*N); // hardcoded for this test
    Gi.resize(gens_needed);
    Hi.resize(gens_needed);
    for (std::size_t i = 0; i < gens_needed; i++) {
        Gi[i].randomize();
        Hi[i].randomize();
    }

    // Commitments
    std::vector<Scalar> v, r;
    v.resize(M);
    v[0] = Scalar(uint64_t(0));
    v[1] = Scalar(uint64_t(1));
    v[2] = Scalar(uint64_t(2));
    v[3] = Scalar(uint64_t(3));
    v[4] = Scalar(std::numeric_limits<uint64_t>::max()) + Scalar(uint64_t(1)); // out of range
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
    std::size_t B = 5; // number of proofs in batch
    std::vector<std::size_t> sizes = {1, 2, 3, 4, 5};
    BOOST_CHECK_EQUAL(sizes.size(), B);

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    Gi.resize(8*N);
    Hi.resize(8*N);
    for (std::size_t i = 0; i < 8*N; i++) {
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
        std::size_t M = sizes[i];
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
    std::size_t B = 5; // number of proofs in batch
    std::vector<std::size_t> sizes = {1, 2, 3, 4, 5};
    BOOST_CHECK_EQUAL(sizes.size(), B);

    // Generators
    GroupElement G, H;
    G.randomize();
    H.randomize();

    std::vector<GroupElement> Gi, Hi;
    Gi.resize(8*N);
    Hi.resize(8*N);
    for (std::size_t i = 0; i < 8*N; i++) {
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
        std::size_t M = sizes[i];
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
