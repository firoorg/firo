// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"

#include "../libspark/params.h"
#include "../libspark/schnorr.h"

#include <cstdlib>
#include <cstddef>
#include <vector>

namespace {

using secp_primitives::GroupElement;
using secp_primitives::Scalar;

struct SchnorrTestData {
    std::size_t n; // number of keys

    GroupElement G;
    std::vector<Scalar> y;
    std::vector<GroupElement> Y;

    explicit SchnorrTestData(const std::size_t n_)
        : n(n_)
    {
        G = spark::Params::get_default()->get_H();

        y.resize(n);
        Y.resize(n);

        for (std::size_t i = 0; i < n; ++i) {
            y[i].randomize();
            Y[i] = G * y[i];
        }
    }
};

void RequireValid(const bool result)
{
    if (!result) {
        std::abort();
    }
}

void SchnorrProveKeys(benchmark::State& state, const std::size_t keys)
{
    SchnorrTestData data(keys);
    spark::Schnorr schnorr(data.G);

    while (state.KeepRunning()) {
        spark::SchnorrProof proof;
        if (keys == 1) {
            schnorr.prove(data.y[0], data.Y[0], proof);
        } else {
            schnorr.prove(data.y, data.Y, proof);
        }
    }
}

void SchnorrVerifyKeys(benchmark::State& state, const std::size_t keys)
{
    SchnorrTestData data(keys);
    spark::Schnorr schnorr(data.G);
    spark::SchnorrProof proof;

    if (keys == 1) {
        schnorr.prove(data.y[0], data.Y[0], proof);
        while (state.KeepRunning()) {
            RequireValid(schnorr.verify(data.Y[0], proof));
        }
    } else {
        schnorr.prove(data.y, data.Y, proof);
        while (state.KeepRunning()) {
            RequireValid(schnorr.verify(data.Y, proof));
        }
    }
}

void SparkSchnorrProve1Key(benchmark::State& state)
{
    SchnorrProveKeys(state, 1);
}

void SparkSchnorrProve2Keys(benchmark::State& state)
{
    SchnorrProveKeys(state, 2);
}

void SparkSchnorrProve4Keys(benchmark::State& state)
{
    SchnorrProveKeys(state, 4);
}

void SparkSchnorrProve8Keys(benchmark::State& state)
{
    SchnorrProveKeys(state, 8);
}

void SparkSchnorrVerify1Key(benchmark::State& state)
{
    SchnorrVerifyKeys(state, 1);
}

void SparkSchnorrVerify2Keys(benchmark::State& state)
{
    SchnorrVerifyKeys(state, 2);
}

void SparkSchnorrVerify4Keys(benchmark::State& state)
{
    SchnorrVerifyKeys(state, 4);
}

void SparkSchnorrVerify8Keys(benchmark::State& state)
{
    SchnorrVerifyKeys(state, 8);
}

} // namespace

BENCHMARK(SparkSchnorrProve1Key);
BENCHMARK(SparkSchnorrProve2Keys);
BENCHMARK(SparkSchnorrProve4Keys);
BENCHMARK(SparkSchnorrProve8Keys);
BENCHMARK(SparkSchnorrVerify1Key);
BENCHMARK(SparkSchnorrVerify2Keys);
BENCHMARK(SparkSchnorrVerify4Keys);
BENCHMARK(SparkSchnorrVerify8Keys);
