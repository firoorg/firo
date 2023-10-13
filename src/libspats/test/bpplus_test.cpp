#include "../bpplus.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

// Generate and verify a single aggregated proof wint no padding
namespace spats {

    BOOST_FIXTURE_TEST_SUITE(spats_bpplus_tests, BasicTestingSetup)

    // Generate and verify a single aggregated proof with no padding
    BOOST_AUTO_TEST_CASE(completeness_single_unpadded)
    {
        // Parameters
        std::size_t N = 64; // bit length
        std::size_t M = 4; // aggregation

        // Generators
        GroupElement E, F, G, H;
        E.randomize();
        F.randomize();
        G.randomize();
        H.randomize();

        std::vector<GroupElement> Gi, Hi;
        std::size_t gens_needed = N * M;

        if (!is_nonzero_power_of_2(gens_needed)) {
            gens_needed = 1 << (log2(N * M) + 1);
        }

        BOOST_CHECK_EQUAL(gens_needed, N * M);

        Gi.resize(gens_needed);
        Hi.resize(gens_needed);
        for (std::size_t i = 0; i < gens_needed; i++) {
            Gi[i].randomize();
            Hi[i].randomize();
        }
        
        // Commitments
        Scalar asset_type = Scalar(uint64_t(1));
        Scalar identifier = Scalar(uint64_t(1));
        std::vector<Scalar> v, r;
        v.resize(M);
        for (int i = 0; i < M; i++) {
            v[i] = Scalar(uint64_t(i));
        }
        r.resize(M);
        std::vector<GroupElement> C;
        C.resize(M);
        for (std::size_t j = 0; j < M; j++) {
            r[j].randomize();
            C[j] = E*asset_type + F*identifier + G*v[j] + H*r[j];
        }

        BPPlus bpplus(E, F, G, H, Gi, Hi, N);
        BPPlusProof proof;
        bpplus.prove(asset_type, identifier, v, r, C, proof);

        auto check = bpplus.verify(C, proof);
        std::cout << "size M: " << M << " " << "check : " << check << std::endl;
        BOOST_CHECK(check);
    }

    // Generate and verifly a single aggregated proof with padding
    BOOST_AUTO_TEST_CASE(completeness_single_padded)
    {
        // Paarmeters
        std::size_t N = 64; // bit length
        std::size_t M = 5; // aggregation

        // Generators
        GroupElement E, F, G, H;
        E.randomize();
        F.randomize();
        G.randomize();
        H.randomize();

        std::vector<GroupElement> Gi, Hi;
        std::size_t gens_needed = N * M;
        if (!is_nonzero_power_of_2(gens_needed)) {
            gens_needed = 1 << (log2(N * M) + 1);
        }
        BOOST_CHECK_EQUAL(gens_needed, 8*N);  // hardcoded for this test
        Gi.resize(gens_needed);
        Hi.resize(gens_needed);
        for (std::size_t i = 0; i < gens_needed; i++) {
            Gi[i].randomize();
            Hi[i].randomize();
        }

        // Commitments
        Scalar asset_type = Scalar(uint64_t(0));
        Scalar identifier = Scalar(uint64_t(0));
        std::vector<Scalar> v, r;

        v.resize(M);
        for (int i = 0; i < M - 1; i++) {
            v[i] = Scalar(uint64_t(i));
        }
        v[M - 1] = Scalar(std::numeric_limits<uint64_t>::max());
        r.resize(M);
        std::vector<GroupElement> C;
        C.resize(M);
        for (std::size_t j = 0; j < M; j++) {
            r[j].randomize();
            C[j] = E*asset_type + F*identifier + G*v[j] + H*r[j];
        }
        
        BPPlus bpplus(E, F, G, H, Gi, Hi, N);
        BPPlusProof proof;
        bpplus.prove(asset_type, identifier, v, r, C, proof);
        auto check = bpplus.verify(C, proof);
        std::cout << "size M: " << M << " " << "check : " << check << std::endl;
        BOOST_CHECK(check);
    }

    // A single proof with invalid value and no padding
    BOOST_AUTO_TEST_CASE(invalid_single_unpadded)
    {
        // Parameters
        std::size_t N = 64; // bit length
        std::size_t M = 4; // aggregation

        // Generators
        GroupElement E, F, G, H;
        E.randomize();
        F.randomize();
        G.randomize();
        H.randomize();

        std::vector<GroupElement> Gi, Hi;
        std::size_t gens_needed = N * M;
        if (!is_nonzero_power_of_2(gens_needed)) {
            gens_needed = 1 << (log2(N * M)+ 1);
        }
        BOOST_CHECK_EQUAL(gens_needed, N * M);
        Gi.resize(gens_needed);
        Hi.resize(gens_needed);
        for (std::size_t i = 0; i < gens_needed; i++) {
            Gi[i].randomize();
            Hi[i].randomize();
        }

        // Commitments
        Scalar asset_type = Scalar(uint64_t(1));
        Scalar identifier = Scalar(uint64_t(1));
        std::vector<Scalar> v, r;
        v.resize(M);
        for (std::size_t i = 0; i < M - 1; i++) {
            v[i] = Scalar(uint64_t(i));
        }
        v[M - 1] = Scalar(std::numeric_limits<uint64_t>::max()) + Scalar(uint64_t(1)); // out of range
        r.resize(M);
        std::vector<GroupElement> C;
        C.resize(M);
        for (std::size_t j = 0; j < M; j++) {
            r[j].randomize();
            C[j] = E*asset_type + F*identifier + G*v[j] + H*r[j];
        }

        BPPlus bpplus(E, F, G, H, Gi, Hi, N);
        BPPlusProof proof;
        bpplus.prove(asset_type, identifier, v, r, C, proof);

        auto check = bpplus.verify(C, proof);
        std::cout << "size M: " << M << " " << "check : " << check << std::endl;
        BOOST_CHECK(!check);
    }

    // A single proof with invalid value and padding
    BOOST_AUTO_TEST_CASE(invalid_single_padding)
    {
        // Parameters
        std::size_t N = 64; // bit length
        std::size_t M = 5; // aggregation

        // Generators
        GroupElement E, F, G, H;
        E.randomize();
        F.randomize();
        G.randomize();
        H.randomize();

        std::vector<GroupElement> Gi, Hi;
        std::size_t gens_needed = N * M;
        if (!is_nonzero_power_of_2(gens_needed)) {
            gens_needed = 1 << (log2(N * M) + 1);
        }
        BOOST_CHECK_EQUAL(gens_needed, 8 * N); // hardcoded for this test
        Gi.resize(gens_needed);
        Hi.resize(gens_needed);
        for (std::size_t i = 0; i < gens_needed; i++) {
            Gi[i].randomize();
            Hi[i].randomize();
        }

        // Commitments
        Scalar asset_type = Scalar(uint64_t(0));
        Scalar identifier = Scalar(uint64_t(0));
        std::vector<Scalar> v, r;
        v.resize(M);
        for (std::size_t i = 0; i < M - 1; i++) {
            v[i] = Scalar(uint64_t(i));
        }
        v[M - 1] = Scalar(std::numeric_limits<uint64_t>::max()) + Scalar(uint64_t(1)); // out of range
        r.resize(M);
        std::vector<GroupElement> C;
        C.resize(M);
        for (std::size_t j = 0; j < M; j++) {
            r[j].randomize();
            C[j] = E*asset_type + F*identifier + G*v[j] + H*r[j];
        }
        BPPlus bpplus(E, F, G, H, Gi, Hi, N);
        BPPlusProof proof;
        bpplus.prove(asset_type, identifier, v, r, C, proof);
        auto check = bpplus.verify(C, proof);
        std::cout << "size M: " << M << " " << "check : " << check << std::endl;
        BOOST_CHECK(!check);
    }

    // Generate and verify a batch of proofs withh variable aggregation
    BOOST_AUTO_TEST_CASE(completeness_batch)
    {
        // Parameters
        std::size_t N = 64; // bit length
        std::size_t B = 5; // number of proofs in batch
        std::vector<std::size_t> sizes = {1,2,3,4,5};
        BOOST_CHECK_EQUAL(sizes.size(), B);

        // Generators
        GroupElement E, F, G, H;
        E.randomize();
        F.randomize();
        G.randomize();
        H.randomize();

        std::vector<GroupElement> Gi, Hi;
        Gi.resize(8 * N);
        Hi.resize(8 * N);
        for (std::size_t i = 0; i < 8 * N; i++) {
            Gi[i].randomize();
            Hi[i].randomize();
        }

        BPPlus bpplus(E, F, G, H, Gi, Hi, N);
        std::vector<BPPlusProof> proofs;
        proofs.resize(B);
        std::vector<std::vector<GroupElement>> C;

        Scalar asset_type = Scalar(uint64_t(0));
        Scalar identifier = Scalar(uint64_t(0));

        // Buid each proof
        for (std::size_t i = 0; i < B; i++) {
            // Commitments
            std::size_t M = sizes[i];
            std::vector<Scalar> v, r;
            asset_type.randomize();
            identifier.randomize();
            v.resize(M);
            r.resize(M);
            std::vector<GroupElement> C_;
            C_.resize(M);
            for (std::size_t j = 0; j < M; j++) {
                v[j] = Scalar(uint64_t(j));
                r[j].randomize();
                C_[j] = E*asset_type + F*identifier + G*v[j] + H*r[j];
            }
            C.emplace_back(C_);
            bpplus.prove(asset_type, identifier, v, r, C_, proofs[i]);
        }
        auto check = bpplus.verify(C, proofs);
        std::cout << "size B: " << B << " " << "check : " << check << std::endl;
        BOOST_CHECK(check);
    }

    // An invalid batch of proofs
    BOOST_AUTO_TEST_CASE(invalid_batch)
    {
        // Parameters
        std::size_t N = 64; // bit length
        std::size_t B = 5; // number of proofs in batch
        std::vector<std::size_t> sizes = {1,2,3,4,5};
        BOOST_CHECK_EQUAL(sizes.size(), B);

        // Generators
        GroupElement E, F, G, H;
        E.randomize();
        F.randomize();
        G.randomize();
        H.randomize();

        std::vector<GroupElement> Gi, Hi;
        Gi.resize(8 * N);
        Hi.resize(8 * N);
        for (std::size_t i = 0; i < 8 * N; i++) {
            Gi[i].randomize();
            Hi[i].randomize();
        }

        BPPlus bpplus(E, F, G, H, Gi, Hi, N);
        std::vector<BPPlusProof> proofs;
        proofs.resize(B);
        std::vector<std::vector<GroupElement>> C;

        Scalar asset_type = Scalar(uint64_t(0));
        Scalar identifier = Scalar(uint64_t(0));

        // Buid each proof
        for (std::size_t i = 0; i < B; i++) {
            // Commitments
            std::size_t M = sizes[i];
            std::vector<Scalar> v, r;
            asset_type.randomize();
            identifier.randomize();
            v.resize(M);
            r.resize(M);
            std::vector<GroupElement> C_;
            C_.resize(M);
            for (std::size_t j = 0; j < M; j++) {
                v[j] = Scalar(uint64_t(j));
                if (i == 0 && j == 0) {
                    v[j] = Scalar(std::numeric_limits<uint64_t>::max()) + Scalar(uint64_t(1));
                }
                r[j].randomize();
                C_[j] = E*asset_type + F*identifier + G*v[j] + H*r[j];
            }
            C.emplace_back(C_);
            bpplus.prove(asset_type, identifier, v, r, C_, proofs[i]);
        }
        auto check = bpplus.verify(C, proofs);
        std::cout << "size B: " << B << " " << "check : " << check << std::endl;
        BOOST_CHECK(!check);
    }

    BOOST_AUTO_TEST_SUITE_END()

} // namespace spats
