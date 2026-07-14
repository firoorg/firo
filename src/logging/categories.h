// Copyright (c) The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_CATEGORIES_H
#define BITCOIN_LOGGING_CATEGORIES_H

#include <cstdint>

// relic exposes its benchmark iteration count as a generic BENCH macro. It is
// not part of Firo's public API and collides with Bitcoin Core's category name.
#ifdef BENCH
#undef BENCH
#endif
#ifdef RAND
#undef RAND
#endif

namespace BCLog {

using CategoryMask = uint64_t;

/**
 * Logging categories selectable with -debug=<category>.
 *
 * Keep the values stable: callers may combine flags and the logger stores them
 * in an atomic bit mask. Firo-specific categories are represented directly
 * instead of relying on the legacy arbitrary-string compatibility path.
 */
enum LogFlags : CategoryMask {
    NONE = CategoryMask{0},
    NET = (CategoryMask{1} << 0),
    TOR = (CategoryMask{1} << 1),
    MEMPOOL = (CategoryMask{1} << 2),
    HTTP = (CategoryMask{1} << 3),
    BENCH = (CategoryMask{1} << 4),
    ZMQ = (CategoryMask{1} << 5),
    WALLETDB = (CategoryMask{1} << 6),
    RPC = (CategoryMask{1} << 7),
    ESTIMATEFEE = (CategoryMask{1} << 8),
    ADDRMAN = (CategoryMask{1} << 9),
    SELECTCOINS = (CategoryMask{1} << 10),
    REINDEX = (CategoryMask{1} << 11),
    CMPCTBLOCK = (CategoryMask{1} << 12),
    RAND = (CategoryMask{1} << 13),
    PRUNE = (CategoryMask{1} << 14),
    PROXY = (CategoryMask{1} << 15),
    MEMPOOLREJ = (CategoryMask{1} << 16),
    LIBEVENT = (CategoryMask{1} << 17),
    COINDB = (CategoryMask{1} << 18),
    QT = (CategoryMask{1} << 19),
    LEVELDB = (CategoryMask{1} << 20),
    VALIDATION = (CategoryMask{1} << 21),
    I2P = (CategoryMask{1} << 22),
    IPC = (CategoryMask{1} << 23),
    LOCK = (CategoryMask{1} << 24),
    BLOCKSTORAGE = (CategoryMask{1} << 25),
    TXRECONCILIATION = (CategoryMask{1} << 26),
    SCAN = (CategoryMask{1} << 27),
    TXPACKAGES = (CategoryMask{1} << 28),
    KERNEL = (CategoryMask{1} << 29),
    PRIVBROADCAST = (CategoryMask{1} << 30),

    // Firo-specific and legacy Firo categories.
    ALERT = (CategoryMask{1} << 31),
    CHAINLOCKS = (CategoryMask{1} << 32),
    DB = (CategoryMask{1} << 33),
    GOBJECT = (CategoryMask{1} << 34),
    INSTANTSEND = (CategoryMask{1} << 35),
    LLMQ = (CategoryMask{1} << 36),
    LLMQ_DKG = (CategoryMask{1} << 37),
    LLMQ_SIGS = (CategoryMask{1} << 38),
    MNPAYMENTS = (CategoryMask{1} << 39),
    MNSYNC = (CategoryMask{1} << 40),
    DBINDEX = (CategoryMask{1} << 41),

    ALL = ~NONE,
};

} // namespace BCLog

#endif // BITCOIN_LOGGING_CATEGORIES_H
