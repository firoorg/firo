// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef FIRO_WALLET_SPARKSPENDBATCH_H
#define FIRO_WALLET_SPARKSPENDBATCH_H

#include "amount.h"
#include "spark/primitives.h"
#include "uint256.h"
#include "wallet/coincontrol.h"
#include "wallet/sparkbatchplanner.h"
#include "wallet/wallet.h"

#include <stdexcept>
#include <string>
#include <vector>

namespace sparkspendbatch {

constexpr size_t MAX_SINGLE_INPUT_SPARK_TRANSACTIONS = 50;

/**
 * Thrown when one or more single-input Spark spends were already broadcast
 * before a later batch failed. Callers must surface the committed txids and
 * must not retry the whole payment.
 */
class SparkSpendBatchPartialFailure : public std::runtime_error
{
public:
    SparkSpendBatchPartialFailure(
        std::string reason,
        std::vector<uint256> committedTxids,
        CAmount committedFee,
        size_t plannedTransactions);

    const std::vector<uint256>& GetCommittedTxids() const { return m_committedTxids; }
    CAmount GetCommittedFee() const { return m_committedFee; }
    size_t GetPlannedTransactions() const { return m_plannedTransactions; }

private:
    std::vector<uint256> m_committedTxids;
    CAmount m_committedFee;
    size_t m_plannedTransactions;
};

bool CompareSparkCoins(const CSparkMintMeta& a, const CSparkMintMeta& b);

bool HasMultipleSelectedCoins(const CCoinControl* coinControl);

CAmount EstimateSingleInputSparkFee(size_t privateOutputs, size_t transparentOutputs);

/** Requires cs_main to be held. */
spark::BatchPlanLimits BuildBatchPlanLimits();

std::vector<CWalletTx> SpendAndStoreSingleInputBatches(
    CWallet& wallet,
    const std::vector<CRecipient>& recipients,
    const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients,
    CAmount& totalFee,
    const CCoinControl* coinControl = nullptr);

} // namespace sparkspendbatch

#endif // FIRO_WALLET_SPARKSPENDBATCH_H
