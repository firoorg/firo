// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_SPECIALTX_H
#define DASH_SPECIALTX_H

#include "primitives/transaction.h"
#include "streams.h"
#include "version.h"

class CBlock;
class CBlockIndex;
class CValidationState;

bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
/**
 * Apply special-transaction state for a connected block (MN list and quorums).
 * @param[in] block Block whose special transactions are processed.
 * @param[in] pindex Index of that block; pindex->pprev is the previous block.
 * @param[out] state Filled on failure.
 * @param[in] fJustCheck If true, MN-list processing does not persist.
 * @param[in] fCheckCbTxMerleRoots If true, coinbase MN-list merkle roots are checked.
 * @param[in] fNotify If true, emit MN-list notifications.
 * @return true if processing succeeds.
 * @pre pindex is non-null.
 * @pre VerifyDB callers pass fNotify as false.
 */
bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex,
                              CValidationState& state, bool fJustCheck,
                              bool fCheckCbTxMerleRoots, bool fNotify = true);
/**
 * Roll back special-transaction state for a disconnected block.
 * @param[in] block Block being disconnected.
 * @param[in] pindex Index of that block.
 * @param[in] fNotify If true, emit MN and quorum rollback notifications.
 * @return true if undo succeeds.
 * @pre pindex is non-null.
 * @pre VerifyDB callers pass fNotify as false.
 */
bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex,
                           bool fNotify = true);

template <typename T>
inline bool GetTxPayload(const std::vector<unsigned char>& payload, T& obj)
{
    CDataStream ds(payload, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ds >> obj;
    } catch (std::exception& e) {
        return false;
    }
    return ds.empty();
}
template <typename T>
inline bool GetTxPayload(const CMutableTransaction& tx, T& obj)
{
    return GetTxPayload(tx.vExtraPayload, obj);
}
template <typename T>
inline bool GetTxPayload(const CTransaction& tx, T& obj)
{
    return GetTxPayload(tx.vExtraPayload, obj);
}

template <typename T>
void SetTxPayload(CMutableTransaction& tx, const T& payload)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << payload;
    tx.vExtraPayload.assign(ds.begin(), ds.end());
}

uint256 CalcTxInputsHash(const CTransaction& tx);

#endif //DASH_SPECIALTX_H
