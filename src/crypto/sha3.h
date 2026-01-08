// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA3_H
#define BITCOIN_CRYPTO_SHA3_H

#include <stdint.h>
#include <stdlib.h>

//! The output size of SHA3-256 in bytes.
static constexpr size_t SHA3_256_OUTPUT_SIZE = 32;

/** A class for SHA3-256. */
class SHA3_256
{
private:
    uint64_t m_state[25] = {0};
    unsigned char m_buffer[136]; // rate bytes (1600 - 256*2) / 8 = 136
    size_t m_bufsize = 0;
    size_t m_pos = 0;
    bool m_finalized = false;

public:
    SHA3_256() = default;
    SHA3_256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[SHA3_256_OUTPUT_SIZE]);
    SHA3_256& Reset();
};

/** Compute SHA3-256 of input. */
void SHA3_256_Final(unsigned char hash[SHA3_256_OUTPUT_SIZE], const unsigned char* data, size_t len);

#endif // BITCOIN_CRYPTO_SHA3_H
