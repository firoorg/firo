// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"

#include "../libspark/bpplus.h"
#include "../libspark/params.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

using secp_primitives::GroupElement;
using secp_primitives::Scalar;

std::size_t NextPowerOfTwo(const std::size_t n)
{
    if (spark::is_nonzero_power_of_2(n)) {
        return n;
    }

    return std::size_t{1} << (spark::log2(n) + 1);
}

void RequireValid(const bool result)
{
    if (!result) {
        std::abort();
    }
}

struct BPPlusTestData {
    std::size_t N;
    std::size_t num_outputs;

    GroupElement G;
    GroupElement H;
    std::vector<GroupElement> Gi;
    std::vector<GroupElement> Hi;

    std::vector<Scalar> v;
    std::vector<Scalar> r;
    std::vector<GroupElement> C;

    BPPlusTestData(const std::size_t N_, const std::size_t num_outputs_)
        : N(N_)
        , num_outputs(num_outputs_)
    {
        const spark::Params* params = spark::Params::get_default();
        G = params->get_G();
        H = params->get_H();

        const std::size_t padded_outputs = NextPowerOfTwo(num_outputs);
        const std::size_t required_generators = N * padded_outputs;
        const std::vector<GroupElement>& default_Gi = params->get_G_range();
        const std::vector<GroupElement>& default_Hi = params->get_H_range();
        if (required_generators > default_Gi.size() || required_generators > default_Hi.size()) {
            throw std::invalid_argument("BPPlus benchmark exceeds default Spark range generators");
        }
        Gi.assign(default_Gi.begin(), default_Gi.begin() + required_generators);
        Hi.assign(default_Hi.begin(), default_Hi.begin() + required_generators);

        v.resize(num_outputs);
        r.resize(num_outputs);
        C.resize(num_outputs);
        for (std::size_t i = 0; i < num_outputs; ++i) {
            v[i] = Scalar(static_cast<uint64_t>(i + 1));
            r[i].randomize();
            C[i] = G * v[i] + H * r[i];
        }
    }
};

struct BPPlusBatchData {
    BPPlusTestData params;
    std::vector<spark::BPPlusProof> proofs;
    std::vector<std::vector<GroupElement>> commitments;

    BPPlusBatchData(const std::size_t num_proofs, const std::size_t outputs_per_proof)
        : params(64, outputs_per_proof)
    {
        spark::BPPlus bpplus(params.G, params.H, params.Gi, params.Hi, params.N);

        proofs.resize(num_proofs);
        commitments.reserve(num_proofs);
        for (std::size_t i = 0; i < num_proofs; ++i) {
            std::vector<Scalar> v(outputs_per_proof);
            std::vector<Scalar> r(outputs_per_proof);
            std::vector<GroupElement> C(outputs_per_proof);

            for (std::size_t j = 0; j < outputs_per_proof; ++j) {
                v[j] = Scalar(static_cast<uint64_t>((i + 1) * (j + 1)));
                r[j].randomize();
                C[j] = params.G * v[j] + params.H * r[j];
            }

            bpplus.prove(v, r, C, proofs[i]);
            commitments.emplace_back(C);
        }
    }
};

void BPPlusProve(benchmark::State& state, const std::size_t bit_length, const std::size_t outputs)
{
    BPPlusTestData data(bit_length, outputs);
    spark::BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);

    while (state.KeepRunning()) {
        spark::BPPlusProof proof;
        bpplus.prove(data.v, data.r, data.C, proof);
    }
}

void BPPlusVerify(benchmark::State& state, const std::size_t bit_length, const std::size_t outputs)
{
    BPPlusTestData data(bit_length, outputs);
    spark::BPPlus bpplus(data.G, data.H, data.Gi, data.Hi, data.N);

    spark::BPPlusProof proof;
    bpplus.prove(data.v, data.r, data.C, proof);

    while (state.KeepRunning()) {
        RequireValid(bpplus.verify(data.C, proof));
    }
}

void BPPlusBatchVerify(benchmark::State& state, const std::size_t num_proofs)
{
    BPPlusBatchData data(num_proofs, 2);
    spark::BPPlus bpplus(data.params.G, data.params.H, data.params.Gi, data.params.Hi, data.params.N);

    while (state.KeepRunning()) {
        RequireValid(bpplus.verify(data.commitments, data.proofs));
    }
}

void SparkBPPlusProve1Output64Bit(benchmark::State& state)
{
    BPPlusProve(state, 64, 1);
}

void SparkBPPlusProve2Outputs64Bit(benchmark::State& state)
{
    BPPlusProve(state, 64, 2);
}

void SparkBPPlusProve4Outputs64Bit(benchmark::State& state)
{
    BPPlusProve(state, 64, 4);
}

void SparkBPPlusProve8Outputs64Bit(benchmark::State& state)
{
    BPPlusProve(state, 64, 8);
}

void SparkBPPlusProve2Outputs32Bit(benchmark::State& state)
{
    BPPlusProve(state, 32, 2);
}

void SparkBPPlusProve2Outputs128Bit(benchmark::State& state)
{
    BPPlusProve(state, 128, 2);
}

void SparkBPPlusVerify1Output64Bit(benchmark::State& state)
{
    BPPlusVerify(state, 64, 1);
}

void SparkBPPlusVerify2Outputs64Bit(benchmark::State& state)
{
    BPPlusVerify(state, 64, 2);
}

void SparkBPPlusVerify4Outputs64Bit(benchmark::State& state)
{
    BPPlusVerify(state, 64, 4);
}

void SparkBPPlusVerify8Outputs64Bit(benchmark::State& state)
{
    BPPlusVerify(state, 64, 8);
}

void SparkBPPlusBatchVerify10Proofs(benchmark::State& state)
{
    BPPlusBatchVerify(state, 10);
}

void SparkBPPlusBatchVerify50Proofs(benchmark::State& state)
{
    BPPlusBatchVerify(state, 50);
}

} // namespace

BENCHMARK(SparkBPPlusProve1Output64Bit);
BENCHMARK(SparkBPPlusProve2Outputs64Bit);
BENCHMARK(SparkBPPlusProve4Outputs64Bit);
BENCHMARK(SparkBPPlusProve8Outputs64Bit);
BENCHMARK(SparkBPPlusProve2Outputs32Bit);
BENCHMARK(SparkBPPlusProve2Outputs128Bit);
BENCHMARK(SparkBPPlusVerify1Output64Bit);
BENCHMARK(SparkBPPlusVerify2Outputs64Bit);
BENCHMARK(SparkBPPlusVerify4Outputs64Bit);
BENCHMARK(SparkBPPlusVerify8Outputs64Bit);
BENCHMARK(SparkBPPlusBatchVerify10Proofs);
BENCHMARK(SparkBPPlusBatchVerify50Proofs);
