// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "benchmark.h"
#include "../libspark/bpplus.h"
#include "../libspark/params.h"
#include <iostream>

using namespace spark;
using namespace benchmark;

// Helper to generate test data for BPPlus range proofs
struct BPPlusTestData {
    std::size_t N; // bit length
    std::size_t num_outputs;
    
    GroupElement G, H;
    std::vector<GroupElement> Gi, Hi;
    
    std::vector<Scalar> v; // values
    std::vector<Scalar> r; // randomness
    std::vector<GroupElement> C; // commitments
    
    BPPlusTestData(std::size_t N_, std::size_t num_outputs_) : N(N_), num_outputs(num_outputs_) {
        // Generate generators
        G.randomize();
        H.randomize();
        
        // Pad num_outputs to next power of 2 if needed
        std::size_t M = num_outputs;
        if ((M & (M - 1)) != 0) {
            M = 1 << (64 - __builtin_clzll(M));
        }
        
        Gi.resize(N * M);
        Hi.resize(N * M);
        for (std::size_t i = 0; i < N * M; ++i) {
            Gi[i].randomize();
            Hi[i].randomize();
        }
        
        // Generate values and commitments
        v.resize(num_outputs);
        r.resize(num_outputs);
        C.resize(num_outputs);
        
        for (std::size_t i = 0; i < num_outputs; ++i) {
            // Generate random value within range
            uint64_t val = rand() % (1ULL << std::min(N, 32UL));
            v[i] = Scalar(val);
            r[i].randomize();
            
            // Commitment: C = vG + rH
            C[i] = G * v[i] + H * r[i];
        }
    }
};

// Benchmark BPPlus proof generation with different output counts
void bench_bpplus_prove_1output() {
    BPPlusTestData data(64, 1);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BenchRunner runner("BPPlus_Prove_1Output_64bit", 10, 1.0);
    auto metrics = runner.run([&]() {
        BPPlusProof proof;
        bpplus.prove(data.v, data.r, data.C, proof);
    });
    metrics.print();
}

void bench_bpplus_prove_2outputs() {
    BPPlusTestData data(64, 2);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BenchRunner runner("BPPlus_Prove_2Outputs_64bit", 10, 1.0);
    auto metrics = runner.run([&]() {
        BPPlusProof proof;
        bpplus.prove(data.v, data.r, data.C, proof);
    });
    metrics.print();
}

void bench_bpplus_prove_4outputs() {
    BPPlusTestData data(64, 4);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BenchRunner runner("BPPlus_Prove_4Outputs_64bit", 10, 1.0);
    auto metrics = runner.run([&]() {
        BPPlusProof proof;
        bpplus.prove(data.v, data.r, data.C, proof);
    });
    metrics.print();
}

void bench_bpplus_prove_8outputs() {
    BPPlusTestData data(64, 8);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BenchRunner runner("BPPlus_Prove_8Outputs_64bit", 5, 1.0);
    auto metrics = runner.run([&]() {
        BPPlusProof proof;
        bpplus.prove(data.v, data.r, data.C, proof);
    });
    metrics.print();
}

// Benchmark with different bit lengths
void bench_bpplus_prove_32bit() {
    BPPlusTestData data(32, 2);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BenchRunner runner("BPPlus_Prove_2Outputs_32bit", 10, 1.0);
    auto metrics = runner.run([&]() {
        BPPlusProof proof;
        bpplus.prove(data.v, data.r, data.C, proof);
    });
    metrics.print();
}

void bench_bpplus_prove_128bit() {
    BPPlusTestData data(128, 2);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BenchRunner runner("BPPlus_Prove_2Outputs_128bit", 5, 1.0);
    auto metrics = runner.run([&]() {
        BPPlusProof proof;
        bpplus.prove(data.v, data.r, data.C, proof);
    });
    metrics.print();
}

// Benchmark BPPlus proof verification
void bench_bpplus_verify_1output() {
    BPPlusTestData data(64, 1);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BPPlusProof proof;
    bpplus.prove(data.v, data.r, data.C, proof);
    
    BenchRunner runner("BPPlus_Verify_1Output_64bit", 50, 1.0);
    auto metrics = runner.run([&]() {
        bool result = bpplus.verify(data.C, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_bpplus_verify_2outputs() {
    BPPlusTestData data(64, 2);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BPPlusProof proof;
    bpplus.prove(data.v, data.r, data.C, proof);
    
    BenchRunner runner("BPPlus_Verify_2Outputs_64bit", 50, 1.0);
    auto metrics = runner.run([&]() {
        bool result = bpplus.verify(data.C, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_bpplus_verify_4outputs() {
    BPPlusTestData data(64, 4);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BPPlusProof proof;
    bpplus.prove(data.v, data.r, data.C, proof);
    
    BenchRunner runner("BPPlus_Verify_4Outputs_64bit", 50, 1.0);
    auto metrics = runner.run([&]() {
        bool result = bpplus.verify(data.C, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_bpplus_verify_8outputs() {
    BPPlusTestData data(64, 8);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    BPPlusProof proof;
    bpplus.prove(data.v, data.r, data.C, proof);
    
    BenchRunner runner("BPPlus_Verify_8Outputs_64bit", 30, 1.0);
    auto metrics = runner.run([&]() {
        bool result = bpplus.verify(data.C, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

// Benchmark batch verification
void bench_bpplus_batch_verify_10proofs() {
    const size_t num_proofs = 10;
    BPPlusTestData data(64, 2);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    // Generate multiple proofs
    std::vector<BPPlusProof> proofs;
    std::vector<std::vector<GroupElement>> C_vec;

    for (size_t i = 0; i < num_proofs; ++i) {
        // Generate independent values and commitments for each proof
        std::vector<Scalar> v_i(2), r_i(2);
        std::vector<GroupElement> C_i(2);
        for (size_t j = 0; j < 2; ++j) {
            uint64_t val = rand() % (1ULL << 32);
            v_i[j] = Scalar(val);
            r_i[j].randomize();
            C_i[j] = data.G * v_i[j] + data.H * r_i[j];
        }
        BPPlusProof proof;
        bpplus.prove(v_i, r_i, C_i, proof);
        proofs.push_back(proof);
        C_vec.push_back(C_i);
    }

    BenchRunner runner("BPPlus_BatchVerify_10Proofs_2Outputs", 20, 1.0);
    auto metrics = runner.run([&]() {
        bool result = bpplus.verify(C_vec, proofs);
        if (!result) {
            std::cerr << "Batch verification failed!\n";
        }
    });
    metrics.print();
}

void bench_bpplus_batch_verify_50proofs() {
    const size_t num_proofs = 50;
    BPPlusTestData data(64, 2);
    BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);
    
    // Generate multiple proofs
    std::vector<BPPlusProof> proofs;
    std::vector<std::vector<GroupElement>> C_vec;

    for (size_t i = 0; i < num_proofs; ++i) {
        // Generate independent values and commitments for each proof
        std::vector<Scalar> v_i(2), r_i(2);
        std::vector<GroupElement> C_i(2);
        for (size_t j = 0; j < 2; ++j) {
            uint64_t val = rand() % (1ULL << 32);
            v_i[j] = Scalar(val);
            r_i[j].randomize();
            C_i[j] = data.G * v_i[j] + data.H * r_i[j];
        }
        BPPlusProof proof;
        bpplus.prove(v_i, r_i, C_i, proof);
        proofs.push_back(proof);
        C_vec.push_back(C_i);
    }
    
    BenchRunner runner("BPPlus_BatchVerify_50Proofs_2Outputs", 10, 1.0);
    auto metrics = runner.run([&]() {
        bool result = bpplus.verify(C_vec, proofs);
        if (!result) {
            std::cerr << "Batch verification failed!\n";
        }
    });
    metrics.print();
}

int main() {
    std::cout << "=== Spark BPPlus (Bulletproofs+) Benchmarks ===\n\n";
    
    std::cout << "--- Proof Generation (varying output count) ---\n";
    bench_bpplus_prove_1output();
    bench_bpplus_prove_2outputs();
    bench_bpplus_prove_4outputs();
    bench_bpplus_prove_8outputs();
    
    std::cout << "\n--- Proof Generation (varying bit length) ---\n";
    bench_bpplus_prove_32bit();
    bench_bpplus_prove_128bit();
    
    std::cout << "\n--- Proof Verification ---\n";
    bench_bpplus_verify_1output();
    bench_bpplus_verify_2outputs();
    bench_bpplus_verify_4outputs();
    bench_bpplus_verify_8outputs();
    
    std::cout << "\n--- Batch Verification ---\n";
    bench_bpplus_batch_verify_10proofs();
    bench_bpplus_batch_verify_50proofs();
    
    return 0;
}
