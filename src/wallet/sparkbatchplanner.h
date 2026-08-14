// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef FIRO_WALLET_SPARKBATCHPLANNER_H
#define FIRO_WALLET_SPARKBATCHPLANNER_H

#include "amount.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace spark {

struct BatchRecipient
{
    CAmount amount{0};
    bool isPrivate{false};
    CAmount minimumOutputAmount{1};
    /** When true, amount is the gross value taken from the coin and the fee is
     *  deducted from this recipient's output (same as CRecipient::fSubtractFeeFromAmount). */
    bool subtractFeeFromAmount{false};
};

struct BatchFragment
{
    size_t recipientIndex{0};
    CAmount amount{0};
};

struct SingleInputBatch
{
    size_t coinIndex{0};
    std::vector<BatchFragment> fragments;
    size_t privateOutputs{0};
    size_t transparentOutputs{0};
    CAmount transparentAmount{0};
    CAmount amount{0};
    CAmount fee{0};
};

struct BatchPlanLimits
{
    size_t maxTransactions{0};
    size_t maxPrivateOutputs{0};
    CAmount maxTransparentAmount{0};
    CAmount maxFee{0};
    CAmount maxMoney{0};
    uint64_t maxWeight{0};
    uint64_t weightScaleFactor{0};
};

enum class BatchPlanStatus
{
    OK,
    INVALID_AMOUNT,
    TRANSPARENT_LIMIT,
    FEE_TOO_HIGH,
    TOO_MANY_TRANSACTIONS,
    INSUFFICIENT_FUNDS,
};

struct BatchPlanResult
{
    BatchPlanStatus status{BatchPlanStatus::OK};
    std::vector<SingleInputBatch> batches;
};

using BatchFeeEstimator = std::function<CAmount(size_t, size_t)>;
using BatchSizeEstimator = std::function<unsigned int(size_t, size_t)>;

unsigned int EstimateSingleInputSparkSize(
    size_t privateOutputs,
    size_t transparentOutputs);

BatchPlanResult PlanSingleInputSpend(
    const std::vector<CAmount>& sortedCoinValues,
    const std::vector<BatchRecipient>& recipients,
    const BatchPlanLimits& limits,
    const BatchFeeEstimator& estimateFee,
    const BatchSizeEstimator& estimateSize);

} // namespace spark

#endif // FIRO_WALLET_SPARKBATCHPLANNER_H
