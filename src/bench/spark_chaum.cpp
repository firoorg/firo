// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "benchmark.h"
#include "../libspark/chaum.h"
#include <iostream>

using namespace spark;
using namespace benchmark;

// Helper to generate test data for Chaum proofs
struct ChaumTestData {
    std::size_t n; // number of commitments
    
    GroupElement F, G, H, U;
    Scalar mu;
    
    std::vector<Scalar> x, y, z;
    std::vector<GroupElement> S, T;
    
    ChaumTestData(std::size_t n_) : n(n_) {
        // Generate generators
        F.randomize();
        G.randomize();
        H.randomize();
        U.randomize();
        
        // Generate scalar mu
        mu.randomize();
        
        // Generate witness scalars
        x.resize(n);
        y.resize(n);
        z.resize(n);
        
        for (std::size_t i = 0; i < n; ++i) {
            x[i].randomize();
            y[i].randomize();
            z[i].randomize();
        }
        
        // Generate commitments S and T
        // S[i] = F^x[i] * G^y[i] * H^z[i]
        // T[i] = U^x[i] * G^(mu*y[i])
        S.resize(n);
        T.resize(n);
        
        for (std::size_t i = 0; i < n; ++i) {
            S[i] = F * x[i] + G * y[i] + H * z[i];
            T[i] = (U + G * y[i].negate()) * x[i].inverse();
        }
    }
};

// Benchmark Chaum proof generation with different commitment counts
void bench_chaum_prove_1commitment() {
    ChaumTestData data(1);
    Chaum chaum(data.F, data.G, data.H, data.U);
    
    BenchRunner runner("Chaum_Prove_1Commitment", 100, 1.0);
    auto metrics = runner.run([&]() {
        ChaumProof proof;
        chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    });
    metrics.print();
}

void bench_chaum_prove_2commitments() {
    ChaumTestData data(2);
    Chaum chaum(data.F, data.G, data.H, data.U);
    
    BenchRunner runner("Chaum_Prove_2Commitments", 100, 1.0);
    auto metrics = runner.run([&]() {
        ChaumProof proof;
        chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    });
    metrics.print();
}

void bench_chaum_prove_4commitments() {
    ChaumTestData data(4);
    Chaum chaum(data.F, data.G, data.H, data.U);
    
    BenchRunner runner("Chaum_Prove_4Commitments", 100, 1.0);
    auto metrics = runner.run([&]() {
        ChaumProof proof;
        chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    });
    metrics.print();
}

void bench_chaum_prove_8commitments() {
    ChaumTestData data(8);
    Chaum chaum(data.F, data.G, data.H, data.U);
    
    BenchRunner runner("Chaum_Prove_8Commitments", 50, 1.0);
    auto metrics = runner.run([&]() {
        ChaumProof proof;
        chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    });
    metrics.print();
}

// Benchmark Chaum proof verification
void bench_chaum_verify_1commitment() {
    ChaumTestData data(1);
    Chaum chaum(data.F, data.G, data.H, data.U);
    
    ChaumProof proof;
    chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    
    BenchRunner runner("Chaum_Verify_1Commitment", 500, 1.0);
    auto metrics = runner.run([&]() {
        bool result = chaum.verify(data.mu, data.S, data.T, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_chaum_verify_2commitments() {
    ChaumTestData data(2);
    Chaum chaum(data.F, data.G, data.H, data.U);
    
    ChaumProof proof;
    chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    
    BenchRunner runner("Chaum_Verify_2Commitments", 500, 1.0);
    auto metrics = runner.run([&]() {
        bool result = chaum.verify(data.mu, data.S, data.T, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_chaum_verify_4commitments() {
    ChaumTestData data(4);
    Chaum chaum(data.F, data.G, data.H, data.U);
    
    ChaumProof proof;
    chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    
    BenchRunner runner("Chaum_Verify_4Commitments", 500, 1.0);
    auto metrics = runner.run([&]() {
        bool result = chaum.verify(data.mu, data.S, data.T, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_chaum_verify_8commitments() {
    ChaumTestData data(8);
    Chaum chaum(data.F, data.G, data.H, data.U);
    
    ChaumProof proof;
    chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    
    BenchRunner runner("Chaum_Verify_8Commitments", 500, 1.0);
    auto metrics = runner.run([&]() {
        bool result = chaum.verify(data.mu, data.S, data.T, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

int main() {
    std::cout << "=== Spark Chaum Proof Benchmarks ===\n\n";
    
    std::cout << "--- Proof Generation ---\n";
    bench_chaum_prove_1commitment();
    bench_chaum_prove_2commitments();
    bench_chaum_prove_4commitments();
    bench_chaum_prove_8commitments();
    
    std::cout << "\n--- Proof Verification ---\n";
    bench_chaum_verify_1commitment();
    bench_chaum_verify_2commitments();
    bench_chaum_verify_4commitments();
    bench_chaum_verify_8commitments();
    
    return 0;
}
