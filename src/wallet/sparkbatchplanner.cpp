// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "wallet/sparkbatchplanner.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace spark {

unsigned int EstimateSingleInputSparkSize(
    size_t privateOutputs,
    size_t transparentOutputs)
{
    // Keep this in step with CSparkWallet::SelectSparkCoins: 924 bytes of
    // fixed transaction data, 1803 for one Grootle proof and its auxiliary
    // data, 322 per private output plus one change output, and 34 per
    // transparent output.
    const uint64_t estimatedSize = 924ULL + 1803ULL
        + 322ULL * (static_cast<uint64_t>(privateOutputs) + 1)
        + 34ULL * static_cast<uint64_t>(transparentOutputs);
    if (estimatedSize > std::numeric_limits<unsigned int>::max()) {
        throw std::runtime_error("Spark transaction size is out of range");
    }

    return static_cast<unsigned int>(estimatedSize);
}

BatchPlanResult PlanSingleInputSpend(
    const std::vector<CAmount>& sortedCoinValues,
    const std::vector<BatchRecipient>& recipients,
    const BatchPlanLimits& limits,
    const BatchFeeEstimator& estimateFee,
    const BatchSizeEstimator& estimateSize)
{
    BatchPlanResult result;
    std::vector<CAmount> remaining;
    remaining.reserve(recipients.size());

    CAmount transparentTotal = 0;
    for (const BatchRecipient& recipient : recipients) {
        if (recipient.amount <= 0 || recipient.amount > limits.maxMoney ||
            recipient.minimumOutputAmount <= 0) {
            result.status = BatchPlanStatus::INVALID_AMOUNT;
            return result;
        }
        remaining.push_back(recipient.amount);
        if (!recipient.isPrivate) {
            if (recipient.minimumOutputAmount > limits.maxTransparentAmount) {
                result.status = BatchPlanStatus::TRANSPARENT_LIMIT;
                return result;
            }
            if (transparentTotal > limits.maxMoney - recipient.amount) {
                result.status = BatchPlanStatus::INVALID_AMOUNT;
                return result;
            }
            transparentTotal += recipient.amount;
        }
    }

    size_t recipientIndex = 0;
    for (size_t coinIndex = 0; coinIndex < sortedCoinValues.size(); ++coinIndex) {
        if (recipientIndex == recipients.size()) {
            break;
        }

        const CAmount coinValue = sortedCoinValues[coinIndex];
        if (coinValue <= 0 || coinValue > limits.maxMoney) {
            continue;
        }

        SingleInputBatch batch;
        batch.coinIndex = coinIndex;

        while (recipientIndex < recipients.size()) {
            const BatchRecipient& recipient = recipients[recipientIndex];
            const size_t privateOutputs = batch.privateOutputs + (recipient.isPrivate ? 1 : 0);
            const size_t transparentOutputs = batch.transparentOutputs + (recipient.isPrivate ? 0 : 1);

            if (privateOutputs > limits.maxPrivateOutputs) {
                break;
            }

            const uint64_t estimatedSize = estimateSize(privateOutputs, transparentOutputs);
            if (limits.weightScaleFactor == 0 || estimatedSize * limits.weightScaleFactor >= limits.maxWeight) {
                break;
            }

            const CAmount fee = estimateFee(privateOutputs, transparentOutputs);
            if (fee > limits.maxFee) {
                result.status = BatchPlanStatus::FEE_TOO_HIGH;
                result.batches.clear();
                return result;
            }

            // With subtractFeeFromAmount the entered amount is taken from the
            // coin and the fee is carved out of the output later
            // (SelectSparkCoins does not add the fee to the required value).
            // Without it the coin must cover amount + fee.
            CAmount available;
            if (recipient.subtractFeeFromAmount) {
                if (fee >= coinValue || batch.amount >= coinValue) {
                    break;
                }
                available = coinValue - batch.amount;
            } else {
                if (batch.amount >= coinValue || fee >= coinValue - batch.amount) {
                    break;
                }
                available = coinValue - batch.amount - fee;
            }
            if (!recipient.isPrivate) {
                available = std::min(
                    available,
                    limits.maxTransparentAmount - batch.transparentAmount);
            }
            if (available <= 0) {
                break;
            }

            CAmount fragment = std::min(remaining[recipientIndex], available);
            if (fragment < recipient.minimumOutputAmount) {
                break;
            }
            // Fee is deducted from this output; it must remain funded after that.
            if (recipient.subtractFeeFromAmount && fragment <= fee &&
                remaining[recipientIndex] == fragment && batch.fragments.empty()) {
                break;
            }

            const CAmount remainder = remaining[recipientIndex] - fragment;
            if (remainder > 0 && remainder < recipient.minimumOutputAmount) {
                const CAmount adjustment = recipient.minimumOutputAmount - remainder;
                if (fragment - adjustment < recipient.minimumOutputAmount) {
                    break;
                }
                fragment -= adjustment;
            }
            batch.fragments.push_back({recipientIndex, fragment});
            batch.amount += fragment;
            batch.fee = fee;
            if (recipient.isPrivate) {
                ++batch.privateOutputs;
            } else {
                ++batch.transparentOutputs;
                batch.transparentAmount += fragment;
            }

            remaining[recipientIndex] -= fragment;
            if (remaining[recipientIndex] == 0) {
                ++recipientIndex;
            }
        }

        if (batch.fragments.empty()) {
            continue;
        }

        result.batches.push_back(std::move(batch));
        if (result.batches.size() >= limits.maxTransactions && recipientIndex < recipients.size()) {
            result.status = BatchPlanStatus::TOO_MANY_TRANSACTIONS;
            result.batches.clear();
            return result;
        }
    }

    if (recipientIndex != recipients.size()) {
        result.status = BatchPlanStatus::INSUFFICIENT_FUNDS;
        result.batches.clear();
    }

    return result;
}

} // namespace spark
