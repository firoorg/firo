// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "benchmark.h"
#include "../libspark/schnorr.h"
#include <iostream>

using namespace spark;
using namespace benchmark;

// Helper to generate test data for Schnorr signatures
struct SchnorrTestData {
    std::size_t n; // number of keys
    
    GroupElement G;
    std::vector<Scalar> y;
    std::vector<GroupElement> Y;
    
    SchnorrTestData(std::size_t n_) : n(n_) {
        // Generate generator
        G.randomize();
        
        // Generate key pairs
        y.resize(n);
        Y.resize(n);
        
        for (std::size_t i = 0; i < n; ++i) {
            y[i].randomize();
            Y[i] = G * y[i];
        }
    }
};

// Benchmark Schnorr signature generation (single key)
void bench_schnorr_prove_1key() {
    SchnorrTestData data(1);
    Schnorr schnorr(data.G);
    
    BenchRunner runner("Schnorr_Sign_1Key", 500, 1.0);
    auto metrics = runner.run([&]() {
        SchnorrProof proof;
        schnorr.prove(data.y[0], data.Y[0], proof);
    });
    metrics.print();
}

// Benchmark Schnorr signature generation (multiple keys)
void bench_schnorr_prove_2keys() {
    SchnorrTestData data(2);
    Schnorr schnorr(data.G);
    
    BenchRunner runner("Schnorr_Sign_2Keys", 500, 1.0);
    auto metrics = runner.run([&]() {
        SchnorrProof proof;
        schnorr.prove(data.y, data.Y, proof);
    });
    metrics.print();
}

void bench_schnorr_prove_4keys() {
    SchnorrTestData data(4);
    Schnorr schnorr(data.G);
    
    BenchRunner runner("Schnorr_Sign_4Keys", 500, 1.0);
    auto metrics = runner.run([&]() {
        SchnorrProof proof;
        schnorr.prove(data.y, data.Y, proof);
    });
    metrics.print();
}

void bench_schnorr_prove_8keys() {
    SchnorrTestData data(8);
    Schnorr schnorr(data.G);
    
    BenchRunner runner("Schnorr_Sign_8Keys", 500, 1.0);
    auto metrics = runner.run([&]() {
        SchnorrProof proof;
        schnorr.prove(data.y, data.Y, proof);
    });
    metrics.print();
}

// Benchmark Schnorr signature verification (single key)
void bench_schnorr_verify_1key() {
    SchnorrTestData data(1);
    Schnorr schnorr(data.G);
    
    SchnorrProof proof;
    schnorr.prove(data.y[0], data.Y[0], proof);
    
    BenchRunner runner("Schnorr_Verify_1Key", 1000, 1.0);
    auto metrics = runner.run([&]() {
        bool result = schnorr.verify(data.Y[0], proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

// Benchmark Schnorr signature verification (multiple keys)
void bench_schnorr_verify_2keys() {
    SchnorrTestData data(2);
    Schnorr schnorr(data.G);
    
    SchnorrProof proof;
    schnorr.prove(data.y, data.Y, proof);
    
    BenchRunner runner("Schnorr_Verify_2Keys", 1000, 1.0);
    auto metrics = runner.run([&]() {
        bool result = schnorr.verify(data.Y, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_schnorr_verify_4keys() {
    SchnorrTestData data(4);
    Schnorr schnorr(data.G);
    
    SchnorrProof proof;
    schnorr.prove(data.y, data.Y, proof);
    
    BenchRunner runner("Schnorr_Verify_4Keys", 1000, 1.0);
    auto metrics = runner.run([&]() {
        bool result = schnorr.verify(data.Y, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

void bench_schnorr_verify_8keys() {
    SchnorrTestData data(8);
    Schnorr schnorr(data.G);
    
    SchnorrProof proof;
    schnorr.prove(data.y, data.Y, proof);
    
    BenchRunner runner("Schnorr_Verify_8Keys", 1000, 1.0);
    auto metrics = runner.run([&]() {
        bool result = schnorr.verify(data.Y, proof);
        if (!result) {
            std::cerr << "Verification failed!\n";
        }
    });
    metrics.print();
}

int main() {
    std::cout << "=== Spark Schnorr Signature Benchmarks ===\n\n";
    
    std::cout << "--- Signature Generation ---\n";
    bench_schnorr_prove_1key();
    bench_schnorr_prove_2keys();
    bench_schnorr_prove_4keys();
    bench_schnorr_prove_8keys();
    
    std::cout << "\n--- Signature Verification ---\n";
    bench_schnorr_verify_1key();
    bench_schnorr_verify_2keys();
    bench_schnorr_verify_4keys();
    bench_schnorr_verify_8keys();
    
    return 0;
}
