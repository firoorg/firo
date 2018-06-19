#ifndef MTP_H_
#define MTP_H_

extern "C" {
#include <inttypes.h>
}
#include "uint256.h"
#include <deque>
#include <vector>

/** Solve the hash problem
 *
 * This function will try different nonce until it finds one such that the
 * computed hash is less than the `target` difficulty.
 *
 * \param input         [in]  Serialized block header
 * \param target        [in]  Target difficulty to achieve
 * \param hash_root_mtp [out] Root hash of the merkle tree
 * \param nonce         [out] Found nonce that satisfied the `target`
 * \param block_mtp     [out] Data used to compute hash values
 * \param proof_mtp     [out] Merkle proofs for every element in `block_mtp`
 * \param pow_limit     [in]  Network limit (hash must be less than that)
 * \param output        [out] Resulting hash value for the given `nonce`
 */
void mtp_hash(const char* input,
        uint32_t target,
        uint8_t hash_root_mtp[16],
        unsigned int* nonce,
        uint64_t (&block_mtp)[72*2][128],
        std::deque<std::vector<uint8_t>>* proof_mtp,
        uint256 pow_limit,
        uint256* output);

/** Verify the given nonce does satisfy the given difficulty
 *
 * This function verifies that the provided `nonce` does produce a hash value
 * that is less than `target`.
 *
 * \param input         [in]  Serialized block header
 * \param target        [in]  Target difficulty to achieve
 * \param hash_root_mtp [in]  Root hash of the merkle tree
 * \param nonce         [in]  Nonce to verify
 * \param block_mtp     [in]  Data used to compute hash values
 * \param proof_mtp     [in]  Merkle proofs for every element in `block_mtp`
 * \param pow_limit     [in]  Network limit (hash must be less than that)
 * \param output        [out] Unused
 *
 * \return `true` if `nonce` is valid, `false` otherwise
 */
bool mtp_verify(const char* input,
        const uint32_t target,
        const uint8_t hash_root_mtp[16],
        const unsigned int* nonce,
        const uint64_t (&block_mtp)[72*2][128],
        const std::deque<std::vector<uint8_t>>* proof_mtp,
        uint256 pow_limit,
        uint256* output);

#endif
