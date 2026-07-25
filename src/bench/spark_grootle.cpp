// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"

#include "../libspark/grootle.h"
#include "../random.h"

#include <cstdlib>
#include <cstddef>
#include <vector>

namespace {

using secp_primitives::GroupElement;
using secp_primitives::Scalar;

void RequireValid(const bool result)
{
    if (!result) {
        std::abort();
    }
}

std::size_t Pow(const std::size_t base, const std::size_t exponent)
{
    std::size_t result = 1;
    for (std::size_t i = 0; i < exponent; ++i) {
        result *= base;
    }
    return result;
}

struct GrootleTestData {
    std::size_t n;
    std::size_t m;
    std::size_t set_size;
    std::size_t l;

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

    GrootleTestData(const std::size_t n_, const std::size_t m_)
        : n(n_)
        , m(m_)
        , set_size(Pow(n_, m_))
        , l(set_size / 2)
        , root(32)
    {
        H.randomize();

        Gi.resize(n * m);
        Hi.resize(n * m);
        for (std::size_t i = 0; i < n * m; ++i) {
            Gi[i].randomize();
            Hi[i].randomize();
        }

        s.randomize();
        v.randomize();

        S.resize(set_size);
        V.resize(set_size);
        for (std::size_t i = 0; i < set_size; ++i) {
            S[i].randomize();
            V[i].randomize();
        }

        S1 = S[l] + H * s.negate();
        V1 = V[l] + H * v.negate();

        GetRandBytes(root.data(), static_cast<int>(root.size()));
    }
};

struct GrootleBatchData {
    GrootleTestData data;
    std::vector<spark::GrootleProof> proofs;
    std::vector<GroupElement> S1;
    std::vector<GroupElement> V1;
    std::vector<std::vector<unsigned char>> roots;
    std::vector<std::size_t> sizes;

    explicit GrootleBatchData(const std::size_t num_proofs)
        : data(4, 3)
    {
        spark::Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);

        proofs.resize(num_proofs);
        S1.reserve(num_proofs);
        V1.reserve(num_proofs);
        roots.reserve(num_proofs);
        sizes.reserve(num_proofs);

        for (std::size_t i = 0; i < num_proofs; ++i) {
            const std::size_t l = i % data.set_size;
            Scalar s;
            Scalar v;
            s.randomize();
            v.randomize();

            GroupElement S1_i = data.S[l] + data.H * s.negate();
            GroupElement V1_i = data.V[l] + data.H * v.negate();

            grootle.prove(l, s, data.S, S1_i, v, data.V, V1_i, data.root, proofs[i]);

            S1.emplace_back(S1_i);
            V1.emplace_back(V1_i);
            roots.emplace_back(data.root);
            sizes.emplace_back(data.set_size);
        }
    }
};

void GrootleProve(benchmark::State& state, const std::size_t n, const std::size_t m)
{
    GrootleTestData data(n, m);
    spark::Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);

    while (state.KeepRunning()) {
        spark::GrootleProof proof;
        grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);
    }
}

void GrootleVerify(benchmark::State& state, const std::size_t n, const std::size_t m)
{
    GrootleTestData data(n, m);
    spark::Grootle grootle(data.H, data.Gi, data.Hi, data.n, data.m);

    spark::GrootleProof proof;
    grootle.prove(data.l, data.s, data.S, data.S1, data.v, data.V, data.V1, data.root, proof);

    while (state.KeepRunning()) {
        RequireValid(grootle.verify(data.S, data.S1, data.V, data.V1, data.root, data.set_size, proof));
    }
}

void SparkGrootleProveN4M2(benchmark::State& state)
{
    GrootleProve(state, 4, 2);
}

void SparkGrootleProveN4M3(benchmark::State& state)
{
    GrootleProve(state, 4, 3);
}

void SparkGrootleProveN4M4(benchmark::State& state)
{
    GrootleProve(state, 4, 4);
}

void SparkGrootleProveN8M3(benchmark::State& state)
{
    GrootleProve(state, 8, 3);
}

void SparkGrootleProveN16M3(benchmark::State& state)
{
    GrootleProve(state, 16, 3);
}

void SparkGrootleVerifyN4M2(benchmark::State& state)
{
    GrootleVerify(state, 4, 2);
}

void SparkGrootleVerifyN4M3(benchmark::State& state)
{
    GrootleVerify(state, 4, 3);
}

void SparkGrootleVerifyN4M4(benchmark::State& state)
{
    GrootleVerify(state, 4, 4);
}

void SparkGrootleVerifyN16M3(benchmark::State& state)
{
    GrootleVerify(state, 16, 3);
}

void SparkGrootleBatchVerify10Proofs(benchmark::State& state)
{
    GrootleBatchData batch(10);
    spark::Grootle grootle(batch.data.H, batch.data.Gi, batch.data.Hi, batch.data.n, batch.data.m);

    while (state.KeepRunning()) {
        RequireValid(grootle.verify(
            batch.data.S,
            batch.S1,
            batch.data.V,
            batch.V1,
            batch.roots,
            batch.sizes,
            batch.proofs));
    }
}

} // namespace

BENCHMARK(SparkGrootleProveN4M2);
BENCHMARK(SparkGrootleProveN4M3);
BENCHMARK(SparkGrootleProveN4M4);
BENCHMARK(SparkGrootleProveN8M3);
BENCHMARK(SparkGrootleProveN16M3);
BENCHMARK(SparkGrootleVerifyN4M2);
BENCHMARK(SparkGrootleVerifyN4M3);
BENCHMARK(SparkGrootleVerifyN4M4);
BENCHMARK(SparkGrootleVerifyN16M3);
BENCHMARK(SparkGrootleBatchVerify10Proofs);
