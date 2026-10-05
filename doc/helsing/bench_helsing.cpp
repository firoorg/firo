// Micro-benchmark: cost of the proof systems a Helsing registration would use,
// at Firo's deployed Spark parameters (n = 8, m = 5, N = 32768).
//
//   grootle   : parallel one-of-many proof over a cover set of `set_size` coins
//   chaum v2  : tag proof (single input)
//   schnorr   : representation proof base H (the Pi_val of the revised spec)
//
// Usage: bench_helsing [set_size] [batch_size]

#include "libspark/params.h"
#include "libspark/grootle.h"
#include "libspark/chaum.h"
#include "libspark/schnorr.h"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace spark;
using clock_type = std::chrono::steady_clock;

static double ms_since(const clock_type::time_point& t0)
{
    return std::chrono::duration<double, std::milli>(clock_type::now() - t0).count();
}

static std::vector<GroupElement> random_group_vector(std::size_t n)
{
    std::vector<GroupElement> result(n);
    for (std::size_t i = 0; i < n; ++i) result[i].randomize();
    return result;
}

int main(int argc, char** argv)
{
    const Params* params = Params::get_default();
    const std::size_t n = params->get_n_grootle();
    const std::size_t m = params->get_m_grootle();
    const std::size_t N = (std::size_t)std::pow((double)n, (double)m);
    const std::size_t set_size = argc > 1 ? (std::size_t)std::atoll(argv[1]) : N;
    const std::size_t batch = argc > 2 ? (std::size_t)std::atoll(argv[2]) : 8;

    std::printf("params: n=%zu m=%zu N=%zu  cover set=%zu  batch=%zu\n", n, m, N, set_size, batch);

    const GroupElement& F = params->get_F();
    const GroupElement& G = params->get_G();
    const GroupElement& H = params->get_H();
    const GroupElement& U = params->get_U();

    // ---- cover set --------------------------------------------------------
    auto t0 = clock_type::now();
    std::vector<GroupElement> S = random_group_vector(set_size);
    std::vector<GroupElement> V = random_group_vector(set_size);
    std::printf("cover set generation: %.1f ms\n", ms_since(t0));

    Grootle grootle(H, params->get_G_grootle(), params->get_H_grootle(), n, m);

    // ---- grootle: `batch` proofs over the same set --------------------------
    std::vector<GrootleProof> proofs;
    std::vector<GroupElement> S1, V1;
    std::vector<std::vector<unsigned char>> roots;
    std::vector<std::size_t> sizes;
    double prove_ms = 0;
    for (std::size_t b = 0; b < batch; ++b) {
        std::size_t l = (std::size_t)(std::rand() % (int)set_size);
        Scalar s, v;
        s.randomize();
        v.randomize();
        // Relation: S[l] - S1 = s*H, V[l] - V1 = v*H
        S1.emplace_back(S[l] + (H * s).inverse());
        V1.emplace_back(V[l] + (H * v).inverse());
        Scalar temp;
        temp.randomize();
        std::vector<unsigned char> root(SCALAR_ENCODING);
        temp.serialize(root.data());
        roots.emplace_back(root);
        sizes.emplace_back(set_size);

        proofs.emplace_back();
        t0 = clock_type::now();
        grootle.prove(l, s, S, S1.back(), v, V, V1.back(), roots.back(), proofs.back());
        prove_ms += ms_since(t0);
    }
    std::printf("grootle prove (avg of %zu):          %.1f ms\n", batch, prove_ms / batch);

    std::size_t proof_bytes = proofs[0].memoryRequired();
    std::printf("grootle proof size:                  %zu bytes\n", proof_bytes);

    t0 = clock_type::now();
    bool ok = grootle.verify(S, S1[0], V, V1[0], roots[0], sizes[0], proofs[0]);
    double single_ms = ms_since(t0);
    std::printf("grootle verify single:               %.1f ms (%s)\n", single_ms, ok ? "ok" : "FAIL");

    t0 = clock_type::now();
    ok = grootle.verify(S, S1, V, V1, roots, sizes, proofs);
    double batch_ms = ms_since(t0);
    std::printf("grootle verify batch of %zu:          %.1f ms total, %.1f ms/proof (%s)\n",
                batch, batch_ms, batch_ms / batch, ok ? "ok" : "FAIL");

    // ---- chaum v2, single input ---------------------------------------------
    {
        Scalar x, y, z, mu;
        x.randomize();
        y.randomize();
        z.randomize();
        mu.randomize();
        std::vector<GroupElement> Sc = {F * x + G * y + H * z};
        std::vector<GroupElement> T = {(U + (G * y).inverse()) * x.inverse()};
        ChaumV2Context ctx;
        Chaum chaum(F, G, H, U);
        ChaumProofV2 proof;
        t0 = clock_type::now();
        chaum.prove_v2(mu, ctx, {x}, {y}, {z}, Sc, T, proof);
        double p = ms_since(t0);
        t0 = clock_type::now();
        bool okc = chaum.verify_v2(mu, ctx, Sc, T, proof);
        double vrf = ms_since(t0);
        std::printf("chaum v2 (1 input) prove/verify:     %.2f / %.2f ms (%s), %zu bytes\n",
                    p, vrf, okc ? "ok" : "FAIL", proof.memoryRequired());
    }

    // ---- schnorr base H ------------------------------------------------------
    {
        Scalar y;
        y.randomize();
        GroupElement Y = H * y;
        Schnorr schnorr(H);
        SchnorrProof proof;
        t0 = clock_type::now();
        schnorr.prove(y, Y, proof);
        double p = ms_since(t0);
        t0 = clock_type::now();
        bool oks = schnorr.verify(Y, proof);
        double vrf = ms_since(t0);
        std::printf("schnorr (base H) prove/verify:       %.2f / %.2f ms (%s), %zu bytes\n",
                    p, vrf, oks ? "ok" : "FAIL", proof.memoryRequired());
    }
    return 0;
}
