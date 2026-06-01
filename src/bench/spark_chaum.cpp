// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"

#include "../libspark/chaum.h"
#include "../libspark/params.h"

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

struct ChaumTestData {
    std::size_t n;

    GroupElement F;
    GroupElement G;
    GroupElement H;
    GroupElement U;
    Scalar mu;

    std::vector<Scalar> x;
    std::vector<Scalar> y;
    std::vector<Scalar> z;
    std::vector<GroupElement> S;
    std::vector<GroupElement> T;

    explicit ChaumTestData(const std::size_t n_)
        : n(n_)
    {
        const spark::Params* params = spark::Params::get_default();
        F = params->get_F();
        G = params->get_G();
        H = params->get_H();
        U = params->get_U();
        mu.randomize();

        x.resize(n);
        y.resize(n);
        z.resize(n);
        S.resize(n);
        T.resize(n);

        for (std::size_t i = 0; i < n; ++i) {
            x[i].randomize();
            y[i].randomize();
            z[i].randomize();

            S[i] = F * x[i] + G * y[i] + H * z[i];
            T[i] = (U + G * y[i].negate()) * x[i].inverse();
        }
    }
};

void ChaumProve(benchmark::State& state, const std::size_t commitments)
{
    ChaumTestData data(commitments);
    spark::Chaum chaum(data.F, data.G, data.H, data.U);

    while (state.KeepRunning()) {
        spark::ChaumProof proof;
        chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);
    }
}

void ChaumVerify(benchmark::State& state, const std::size_t commitments)
{
    ChaumTestData data(commitments);
    spark::Chaum chaum(data.F, data.G, data.H, data.U);

    spark::ChaumProof proof;
    chaum.prove(data.mu, data.x, data.y, data.z, data.S, data.T, proof);

    while (state.KeepRunning()) {
        RequireValid(chaum.verify(data.mu, data.S, data.T, proof));
    }
}

void SparkChaumProve1Commitment(benchmark::State& state)
{
    ChaumProve(state, 1);
}

void SparkChaumProve2Commitments(benchmark::State& state)
{
    ChaumProve(state, 2);
}

void SparkChaumProve4Commitments(benchmark::State& state)
{
    ChaumProve(state, 4);
}

void SparkChaumProve8Commitments(benchmark::State& state)
{
    ChaumProve(state, 8);
}

void SparkChaumVerify1Commitment(benchmark::State& state)
{
    ChaumVerify(state, 1);
}

void SparkChaumVerify2Commitments(benchmark::State& state)
{
    ChaumVerify(state, 2);
}

void SparkChaumVerify4Commitments(benchmark::State& state)
{
    ChaumVerify(state, 4);
}

void SparkChaumVerify8Commitments(benchmark::State& state)
{
    ChaumVerify(state, 8);
}

} // namespace

BENCHMARK(SparkChaumProve1Commitment);
BENCHMARK(SparkChaumProve2Commitments);
BENCHMARK(SparkChaumProve4Commitments);
BENCHMARK(SparkChaumProve8Commitments);
BENCHMARK(SparkChaumVerify1Commitment);
BENCHMARK(SparkChaumVerify2Commitments);
BENCHMARK(SparkChaumVerify4Commitments);
BENCHMARK(SparkChaumVerify8Commitments);
