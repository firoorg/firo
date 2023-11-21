// Copyright (c) 2021 Andrea Lanfranchi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once
#ifndef FIRO_PROGPOW_H
#define FIRO_PROGPOW_H

#include <crypto/progpow/include/ethash/ethash.h>
#include <crypto/progpow/include/ethash/progpow.hpp>
#include <uint256.h>
#include <serialize.h>

/**
 * Serializer for ProgPow BlockHeader input
*/
class CProgPowHeader {
public:
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nHeight;

    uint64_t nNonce64;
    uint256 mix_hash;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nHeight);
    }
};

/* Performs a full progpow hash (DAG loops implied) provided header already hash nHeight valued */
uint256 progpow_hash_full(const CProgPowHeader& header, uint256& mix_hash);

/* Performs a light progpow hash (DAG loops excluded) provided header has mix_hash */
uint256 progpow_hash_light(const CProgPowHeader& header);

#endif // FIRO_PROGPOW_H
