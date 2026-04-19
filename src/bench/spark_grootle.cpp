// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "benchmark.h"
#include "../libspark/grootle.h"
#include "../libspark/params.h"
#include "../random.h"
#include <iostream>

using namespace spark;
using namespace benchmark;

// Helper to generate test data for Grootle proofs
struct GrootleTestData {
    std::size_t n;
    std::size_t m;
    std::size_t set_size;
    std::size_t l; // hidden index
    
    GroupElement H;
    std::vector<GroupElement> Gi;
    std::vector<GroupElement> Hi;
    
    Scalar s;
    std::vector<GroupElement> S;
    GroupElement S1;
    
    Scalar v;
    std::vector<GroupElement> V;
    GroupElement V1;
    
    std::vector<unsigned char> root;
    
    GrootleTestData(std::size_t n_, std::size_t m_) : n(n_), m(m_) {
        set_size = 1;
        for (std::size_t i = 0; i < m; ++i) {
            set_size *= n;
        }
        
        // Generate random hidden index
        l = rand() % set_size;
        
        // Generate generators
        H.randomize();
        Gi.resize(n * m);
        Hi.resize(n * m);
        for (std::size_t i = 0; i < n * m; ++i) {
            Gi[i].randomize();
            Hi[i].randomize();
        }
        
        // Generate witness
        s.randomize();
        v.randomize();
        
        // Generate sets S and V
        S.resize(set_size);
        V.resize(set_size);
        for (std::size_t i = 0; i < set_size; ++i) {
            S[i].randomize();
            V[i].randomize();
        }
        
        // Set the actual values at hidden index
        S1 = S[l] + H * s.negate();
        V1 = V[l] + H * v.negate();
        
        // Generate random root
        root.resize(32);
        GetRandBytes(root.data(), 32);
    }
};

// Benchmark Grootle proof generation with different set sizes
void bench_grootle_prove_n4_m2() {
    GrootleTestData data(4, 2); // set size = 16
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    BenchRunner runner("Grootle_Prove_N4_M2_SetSize16", 10, 1.0);
    auto metrics = runner.run([&]() {
        GrootleProof proof;
        grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    });
    metrics.print();
}

void bench_grootle_prove_n4_m3() {
    GrootleTestData data(4, 3); // set size = 64
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    BenchRunner runner("Grootle_Prove_N4_M3_SetSize64", 10, 1.0);
    auto metrics = runner.run([&]() {
        GrootleProof proof;
        grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    });
    metrics.print();
}

void bench_grootle_prove_n4_m4() {
    GrootleTestData data(4, 4); // set size = 256
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    BenchRunner runner("Grootle_Prove_N4_M4_SetSize256", 10, 1.0);
    auto metrics = runner.run([&]() {
        GrootleProof proof;
        grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    });
    metrics.print();
}

void bench_grootle_prove_n8_m3() {
    GrootleTestData data(8, 3); // set size = 512
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    BenchRunner runner("Grootle_Prove_N8_M3_SetSize512", 5, 1.0);
    auto metrics = runner.run([&]() {
        GrootleProof proof;
        grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    });
    metrics.print();
}

void bench_grootle_prove_n16_m3() {
    GrootleTestData data(16, 3); // set size = 4096
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    BenchRunner runner("Grootle_Prove_N16_M3_SetSize4096", 3, 1.0);
    auto metrics = runner.run([&]() {
        GrootleProof proof;
        grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    });
    metrics.print();
}

// Benchmark Grootle proof verification
void bench_grootle_verify_n4_m2() {
    GrootleTestData data(4, 2);
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    GrootleProof proof;
    grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    
    BenchRunner runner("Grootle_Verify_N4_M2_SetSize16", 50, 1.0);
    auto metrics = runner.run([&]() {
        bool result = grootle.verify(data.S, data.S1, data.V, data.V1, data.root, data.set_size, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_grootle_verify_n4_m3() {
    GrootleTestData data(4, 3);
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    GrootleProof proof;
    grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    
    BenchRunner runner("Grootle_Verify_N4_M3_SetSize64", 50, 1.0);
    auto metrics = runner.run([&]() {
        bool result = grootle.verify(data.S, data.S1, data.V, data.V1, data.root, data.set_size, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_grootle_verify_n4_m4() {
    GrootleTestData data(4, 4);
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    GrootleProof proof;
    grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    
    BenchRunner runner("Grootle_Verify_N4_M4_SetSize256", 50, 1.0);
    auto metrics = runner.run([&]() {
        bool result = grootle.verify(data.S, data.S1, data.V, data.V1, data.root, data.set_size, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_grootle_verify_n16_m3() {
    GrootleTestData data(16, 3);
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    GrootleProof proof;
    grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    
    BenchRunner runner("Grootle_Verify_N16_M3_SetSize4096", 20, 1.0);
    auto metrics = runner.run([&]() {
        bool result = grootle.verify(data.S, data.S1, data.V, data.V1, data.root, data.set_size, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

// Benchmark batch verification
void bench_grootle_batch_verify_10proofs() {
    const size_t num_proofs = 10;
    GrootleTestData data(4, 3); // set size = 64
    Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);
    
    // Generate multiple proofs
    std::vector<GrootleProof> proofs;
    std::vector<GroupElement> S1_vec;
    std::vector<GroupElement> V1_vec;
    std::vector<std::vector<unsigned char>> roots;
    std::vector<std::size_t> sizes;
    
    for (size_t i = 0; i < num_proofs; ++i) {
        // Generate independent witness for each proof, but use same anonymity set
        size_t l = rand() % data.set_size;
        Scalar s, v;
        s.randomize();
        v.randomize();
        
        GroupElement S1 = data.S[l] + data.H * s.negate();
        GroupElement V1 = data.V[l] + data.H * v.negate();
        
        GrootleProof proof;
        grootle.prove(l, s, data.S, S1, v, data.V, V1, data.root, proof);
        proofs.push_back(proof);
        S1_vec.push_back(S1);
        V1_vec.push_back(V1);
        roots.push_back(data.root);
        sizes.push_back(data.set_size);
    }
    
    BenchRunner runner("Grootle_BatchVerify_10Proofs_SetSize64", 20, 1.0);
    auto metrics = runner.run([&]() {
        bool result = grootle.verify(data.S, S1_vec, data.V, V1_vec, roots, sizes, proofs);
        if (!result) {
            std::cerr << "Batch verification failed!\n";
        }
    });
    metrics.print();
}

int main() {
    std::cout << "=== Spark Grootle Proof Benchmarks ===\n\n";
    
    std::cout << "--- Proof Generation ---\n";
    bench_grootle_prove_n4_m2();
    bench_grootle_prove_n4_m3();
    bench_grootle_prove_n4_m4();
    bench_grootle_prove_n8_m3();
    bench_grootle_prove_n16_m3();
    
    std::cout << "\n--- Proof Verification ---\n";
    bench_grootle_verify_n4_m2();
    bench_grootle_verify_n4_m3();
    bench_grootle_verify_n4_m4();
    bench_grootle_verify_n16_m3();
    
    std::cout << "\n--- Batch Verification ---\n";
    bench_grootle_batch_verify_10proofs();
    
    return 0;
}
