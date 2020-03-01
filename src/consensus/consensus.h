// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2016-2017 The Zcoin developers

// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdint.h>

// HF constants
static const int HF_LYRA2VAR_HEIGHT = 500;
static const int HF_LYRA2_HEIGHT = 8192;
static const int HF_LYRA2Z_HEIGHT = 20500;
static const int HF_ZNODE_HEIGHT = 66550;
static const int HF_ZNODE_PAYMENT_START = HF_ZNODE_HEIGHT + 150; // 66700 - about 25h after HF
static const int HF_MTP_HEIGHT = 88888;

static const int HF_LYRA2VAR_HEIGHT_TESTNET = 10;
static const int HF_LYRA2_HEIGHT_TESTNET = 25; // for consistent purpose since the algo hash is so low
static const int HF_LYRA2Z_HEIGHT_TESTNET = 30;
static const int HF_ZNODE_HEIGHT_TESTNET = 500;
static const int HF_MTP_HEIGHT_TESTNET = 9999;

static const int HF_ZEROSPEND_FIX = 22000;

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 2000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 2000000;
/** The maximum allowed size for a block excluding witness data, in bytes (network rule) */
static const unsigned int MAX_BLOCK_BASE_SIZE = 2000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 400000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
