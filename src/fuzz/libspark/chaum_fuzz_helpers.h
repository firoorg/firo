#ifndef BITCOIN_FUZZ_LIBSPARK_CHAUM_FUZZ_HELPERS_H
#define BITCOIN_FUZZ_LIBSPARK_CHAUM_FUZZ_HELPERS_H

#include "../../libspark/chaum.h"

#include <cassert>
#include <vector>

inline void assert_v1_rejects_mutations(
    spark::Chaum& chaum,
    const Scalar& mu,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T,
    spark::ChaumProofV1& proof)
{
    const std::size_t n = S.size();

    Scalar evil_mu;
    evil_mu.randomize();
    assert(!(chaum.verify_v1(evil_mu, S, T, proof)));

    for (std::size_t i = 0; i < n; ++i) {
        std::vector<GroupElement> evil_S(S);
        evil_S[i].randomize();
        assert(!(chaum.verify_v1(mu, evil_S, T, proof)));
    }

    for (std::size_t i = 0; i < n; ++i) {
        std::vector<GroupElement> evil_T(T);
        evil_T[i].randomize();
        assert(!(chaum.verify_v1(mu, S, evil_T, proof)));
    }

    spark::ChaumProofV1 evil_proof = proof;
    evil_proof.A1.randomize();
    assert(!(chaum.verify_v1(mu, S, T, evil_proof)));

    for (std::size_t i = 0; i < n; ++i) {
        evil_proof = proof;
        evil_proof.A2[i].randomize();
        assert(!(chaum.verify_v1(mu, S, T, evil_proof)));
    }

    for (std::size_t i = 0; i < n; ++i) {
        evil_proof = proof;
        evil_proof.t1[i].randomize();
        assert(!(chaum.verify_v1(mu, S, T, evil_proof)));
    }

    evil_proof = proof;
    evil_proof.t2.randomize();
    assert(!(chaum.verify_v1(mu, S, T, evil_proof)));

    evil_proof = proof;
    evil_proof.t3.randomize();
    assert(!(chaum.verify_v1(mu, S, T, evil_proof)));
}

#endif // BITCOIN_FUZZ_LIBSPARK_CHAUM_FUZZ_HELPERS_H
