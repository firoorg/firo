// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/sha3.h"
#include <string.h>

// Keccak-f[1600] round constants
static const uint64_t keccak_round_constants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets
static const int keccak_rotation_offsets[25] = {
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
    25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak-f[1600] permutation
static void keccakf1600(uint64_t state[25]) {
    for (int round = 0; round < 24; ++round) {
        // Theta step
        uint64_t C[5], D[5];
        for (int i = 0; i < 5; ++i)
            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        for (int i = 0; i < 5; ++i)
            D[i] = C[(i + 4) % 5] ^ rotl64(C[(i + 1) % 5], 1);
        for (int i = 0; i < 25; ++i)
            state[i] ^= D[i % 5];

        // Rho and Pi steps
        uint64_t temp[25];
        for (int i = 0; i < 25; ++i)
            temp[i] = state[i];
        
        static const int pi[25] = {
            0, 6, 12, 18, 24, 3, 9, 10, 16, 22,
            1, 7, 13, 19, 20, 4, 5, 11, 17, 23,
            2, 8, 14, 15, 21
        };
        for (int i = 0; i < 25; ++i)
            state[pi[i]] = rotl64(temp[i], keccak_rotation_offsets[i]);

        // Chi step
        for (int i = 0; i < 25; i += 5) {
            uint64_t t[5];
            for (int j = 0; j < 5; ++j)
                t[j] = state[i + j];
            for (int j = 0; j < 5; ++j)
                state[i + j] = t[j] ^ ((~t[(j + 1) % 5]) & t[(j + 2) % 5]);
        }

        // Iota step
        state[0] ^= keccak_round_constants[round];
    }
}

SHA3_256& SHA3_256::Write(const unsigned char* data, size_t len) {
    if (m_finalized) return *this;
    
    const size_t rate = 136; // (1600 - 256*2) / 8 = 136 bytes
    
    while (len > 0) {
        size_t to_copy = rate - m_pos;
        if (to_copy > len) to_copy = len;
        
        memcpy(m_buffer + m_pos, data, to_copy);
        m_pos += to_copy;
        data += to_copy;
        len -= to_copy;
        
        if (m_pos == rate) {
            // XOR buffer into state
            for (size_t i = 0; i < rate / 8; ++i) {
                uint64_t v = 0;
                for (int j = 0; j < 8; ++j)
                    v |= ((uint64_t)m_buffer[i * 8 + j]) << (8 * j);
                m_state[i] ^= v;
            }
            keccakf1600(m_state);
            m_pos = 0;
        }
    }
    
    return *this;
}

void SHA3_256::Finalize(unsigned char hash[SHA3_256_OUTPUT_SIZE]) {
    if (m_finalized) return;
    
    const size_t rate = 136;
    
    // SHA3 padding: append 0x06, then zeros, then 0x80
    m_buffer[m_pos] = 0x06;
    memset(m_buffer + m_pos + 1, 0, rate - m_pos - 1);
    m_buffer[rate - 1] |= 0x80;
    
    // XOR final block into state
    for (size_t i = 0; i < rate / 8; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j)
            v |= ((uint64_t)m_buffer[i * 8 + j]) << (8 * j);
        m_state[i] ^= v;
    }
    keccakf1600(m_state);
    
    // Extract hash (first 256 bits = 32 bytes)
    for (size_t i = 0; i < SHA3_256_OUTPUT_SIZE / 8; ++i) {
        for (int j = 0; j < 8; ++j)
            hash[i * 8 + j] = (m_state[i] >> (8 * j)) & 0xFF;
    }
    
    m_finalized = true;
}

SHA3_256& SHA3_256::Reset() {
    memset(m_state, 0, sizeof(m_state));
    memset(m_buffer, 0, sizeof(m_buffer));
    m_pos = 0;
    m_finalized = false;
    return *this;
}

void SHA3_256_Final(unsigned char hash[SHA3_256_OUTPUT_SIZE], const unsigned char* data, size_t len) {
    SHA3_256 ctx;
    ctx.Write(data, len);
    ctx.Finalize(hash);
}
