// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "wallet/sparkspendbatch.h"

#include "chainparams.h"
#include "init.h"
#include "net.h"
#include "policy/policy.h"
#include "spark/state.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "wallet/sparkbatchplanner.h"
#include "wallet/walletexcept.h"

#include <stdexcept>
#include <string>
#include <utility>

namespace sparkspendbatch {
namespace {

struct RecipientEntry
{
    bool isPrivate{false};
    CScript scriptPubKey;
    spark::OutputCoinData privateOutput;
    bool subtractFee{false};
};

struct AvailableCoin
{
    CAmount value{0};
    COutPoint outpoint;
};

struct PreparedBatch
{
    CWalletTx wtx;
    CAmount fee{0};
};

std::string FormatPartialFailureMessage(
    const std::string& reason,
    const std::vector<uint256>& committedTxids,
    size_t plannedTransactions)
{
    std::string txidList;
    for (size_t i = 0; i < committedTxids.size(); ++i) {
        if (i > 0) {
            txidList += ", ";
        }
        txidList += committedTxids[i].ToString();
    }

    return strprintf(
        _("Spark spend batch failed after committing %u of %u transactions: %s. "
          "Do not retry the whole payment. Already sent: %s"),
        committedTxids.size(),
        plannedTransactions,
        reason,
        txidList);
}

bool HasSubtractFee(
    const std::vector<CRecipient>& recipients,
    const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients)
{
    for (const CRecipient& recipient : recipients) {
        if (recipient.fSubtractFeeFromAmount) {
            return true;
        }
    }
    for (const auto& recipient : privateRecipients) {
        if (recipient.second) {
            return true;
        }
    }
    return false;
}

void ThrowForPlanStatus(spark::BatchPlanStatus status)
{
    switch (status) {
    case spark::BatchPlanStatus::OK:
        return;
    case spark::BatchPlanStatus::INVALID_AMOUNT:
        throw std::runtime_error(_("Invalid Spark spend amount."));
    case spark::BatchPlanStatus::TRANSPARENT_LIMIT:
        throw std::runtime_error(_("Spend to transparent address limit exceeded."));
    case spark::BatchPlanStatus::FEE_TOO_HIGH:
        throw std::runtime_error(_("Spark transaction fee is too high."));
    case spark::BatchPlanStatus::TOO_MANY_TRANSACTIONS:
        throw std::runtime_error(strprintf(
            _("A Spark payment may use at most %u transactions."),
            MAX_SINGLE_INPUT_SPARK_TRANSACTIONS));
    case spark::BatchPlanStatus::INSUFFICIENT_FUNDS:
        throw InsufficientFunds(_(
            "The available Spark coins cannot cover the amount and the required transaction fees."));
    }
}

void CommitSparkSpend(CWallet& wallet, CWalletTx& wtx)
{
    CValidationState state;
    CReserveKey reserveKey(&wallet);
    // Match WalletModel::spendSparkCoins: pass GetBroadcastTransactions() as
    // fCheckTransaction so a mempool rejection fails the commit (and thus the
    // batch) instead of being logged while CommitTransaction still returns true.
    // Prefer GetBroadcastTransactions() over true so -walletbroadcast=0 does not
    // force relay via the fCheckTransaction branch in CommitTransaction.
    if (!wallet.CommitTransaction(
            wtx,
            reserveKey,
            g_connman.get(),
            state,
            wallet.GetBroadcastTransactions())) {
        throw std::runtime_error(
            state.GetRejectReason().empty()
                ? _("Transaction commit failed.")
                : state.GetRejectReason());
    }
}

} // namespace

SparkSpendBatchPartialFailure::SparkSpendBatchPartialFailure(
    std::string reason,
    std::vector<uint256> committedTxids,
    CAmount committedFee,
    size_t plannedTransactions)
    : std::runtime_error(FormatPartialFailureMessage(
          reason, committedTxids, plannedTransactions)),
      m_committedTxids(std::move(committedTxids)),
      m_committedFee(committedFee),
      m_plannedTransactions(plannedTransactions)
{
}

bool CompareSparkCoins(const CSparkMintMeta& a, const CSparkMintMeta& b)
{
    if (a.v != b.v) return a.v > b.v;
    if (a.nHeight != b.nHeight) return a.nHeight < b.nHeight;
    if (a.txid != b.txid) return a.txid < b.txid;
    return a.GetNonceHash() < b.GetNonceHash();
}

bool HasMultipleSelectedCoins(const CCoinControl* coinControl)
{
    if (!coinControl || !coinControl->HasSelected()) {
        return false;
    }

    std::vector<COutPoint> selected;
    coinControl->ListSelected(selected);
    return selected.size() > 1;
}

CAmount EstimateSingleInputSparkFee(size_t privateOutputs, size_t transparentOutputs)
{
    const unsigned int estimatedSize =
        spark::EstimateSingleInputSparkSize(privateOutputs, transparentOutputs);

    return std::max(
        payTxFee.GetFeePerK(),
        CWallet::GetMinimumFee(estimatedSize, nTxConfirmTarget, mempool));
}

CAmount TransparentMinimumOutputAmount(const CScript& scriptPubKey)
{
    // CreateSparkSpendTransaction rejects transparent outputs with
    // IsDust(minRelayTxFee). Keep planner fragments at or above that threshold
    // so a later batch cannot fail dust checks after earlier ones are planned.
    const CAmount dust = CTxOut(0, scriptPubKey).GetDustThreshold(::minRelayTxFee);
    return dust > 0 ? dust : 1;
}

spark::BatchPlanLimits BuildBatchPlanLimits()
{
    const auto& consensus = Params().GetConsensus();
    spark::BatchPlanLimits limits;
    limits.maxTransactions = MAX_SINGLE_INPUT_SPARK_TRANSACTIONS;
    limits.maxPrivateOutputs = consensus.nMaxSparkOutLimitPerTx > 1
        ? consensus.nMaxSparkOutLimitPerTx - 2
        : 0;
    limits.maxTransparentAmount =
        consensus.GetMaxValueSparkSpendPerTransaction(chainActive.Height());
    limits.maxFee = maxTxFee;
    limits.maxMoney = MAX_MONEY;
    limits.maxWeight = MAX_NEW_TX_WEIGHT;
    limits.weightScaleFactor = WITNESS_SCALE_FACTOR;
    return limits;
}

std::vector<CWalletTx> SpendAndStoreSingleInputBatches(
    CWallet& wallet,
    const std::vector<CRecipient>& recipients,
    const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients,
    CAmount& totalFee,
    const CCoinControl* coinControl)
{
    if (recipients.empty() && privateRecipients.empty()) {
        throw std::runtime_error(_("No Spark spend recipients were provided."));
    }

    if (HasMultipleSelectedCoins(coinControl)) {
        throw std::runtime_error(_(
            "Spark Coin Control temporarily supports selecting at most one coin. "
            "Clear the selection to let the wallet split the payment automatically."));
    }

    CAmount totalAmount = 0;
    for (const CRecipient& recipient : recipients) {
        if (recipient.nAmount <= 0 || !MoneyRange(recipient.nAmount)) {
            throw std::runtime_error(_("Invalid Spark spend amount."));
        }
        if (totalAmount > MAX_MONEY - recipient.nAmount) {
            throw std::runtime_error(_("Invalid Spark spend amount."));
        }
        totalAmount += recipient.nAmount;
    }
    for (const auto& recipient : privateRecipients) {
        const CAmount amount = static_cast<CAmount>(recipient.first.v);
        if (amount <= 0 || !MoneyRange(amount)) {
            throw std::runtime_error(_("Invalid Spark spend amount."));
        }
        if (totalAmount > MAX_MONEY - amount) {
            throw std::runtime_error(_("Invalid Spark spend amount."));
        }
        totalAmount += amount;
    }

    const CAmount sparkBalance = wallet.GetSparkBalance().first;
    if (totalAmount > sparkBalance) {
        throw InsufficientFunds();
    }

    std::vector<RecipientEntry> recipientEntries;
    recipientEntries.reserve(recipients.size() + privateRecipients.size());
    std::vector<spark::BatchRecipient> plannerRecipients;
    plannerRecipients.reserve(recipientEntries.capacity());

    for (const CRecipient& recipient : recipients) {
        RecipientEntry entry;
        entry.isPrivate = false;
        entry.scriptPubKey = recipient.scriptPubKey;
        entry.subtractFee = recipient.fSubtractFeeFromAmount;
        recipientEntries.push_back(entry);
        plannerRecipients.push_back({
            recipient.nAmount,
            false,
            TransparentMinimumOutputAmount(recipient.scriptPubKey),
            recipient.fSubtractFeeFromAmount});
    }
    for (const auto& recipient : privateRecipients) {
        const CAmount amount = static_cast<CAmount>(recipient.first.v);
        RecipientEntry entry;
        entry.isPrivate = true;
        entry.privateOutput = recipient.first;
        entry.subtractFee = recipient.second;
        recipientEntries.push_back(entry);
        plannerRecipients.push_back({amount, true, 1, recipient.second});
    }

    std::vector<AvailableCoin> availableCoins;
    spark::BatchPlanLimits limits;
    {
        LOCK2(cs_main, wallet.cs_wallet);

        std::list<CSparkMintMeta> coinMetadata = wallet.GetAvailableSparkCoins(coinControl);
        coinMetadata.sort(CompareSparkCoins);
        availableCoins.reserve(coinMetadata.size());
        for (const CSparkMintMeta& coin : coinMetadata) {
            if (coin.v > static_cast<uint64_t>(MAX_MONEY)) {
                continue;
            }

            COutPoint outpoint;
            if (spark::GetOutPoint(outpoint, coin.coin)) {
                availableCoins.push_back({static_cast<CAmount>(coin.v), outpoint});
            }
        }

        limits = BuildBatchPlanLimits();
    }

    std::vector<CAmount> coinValues;
    coinValues.reserve(availableCoins.size());
    for (const AvailableCoin& coin : availableCoins) {
        coinValues.push_back(coin.value);
    }

    spark::BatchPlanResult plan;
    try {
        plan = spark::PlanSingleInputSpend(
            coinValues,
            plannerRecipients,
            limits,
            EstimateSingleInputSparkFee,
            spark::EstimateSingleInputSparkSize);
    } catch (const std::exception& e) {
        throw std::runtime_error(e.what());
    }

    ThrowForPlanStatus(plan.status);

    if (plan.batches.size() > 1 && HasSubtractFee(recipients, privateRecipients)) {
        throw std::runtime_error(_(
            "Subtracting the fee from the amount is temporarily unavailable when a Spark spend must be split across multiple transactions."));
    }

    // Mirror CreateSparkSpendTransaction's fee division: the fee is split
    // across the subtract-fee recipients (transparent first, then private) and
    // the first one also pays the remainder. Reject a recipient that could not
    // cover its share here, with a clear message, instead of failing later
    // inside transaction creation.
    if (plan.batches.size() == 1 && HasSubtractFee(recipients, privateRecipients)) {
        size_t subtractCount = 0;
        for (const CRecipient& recipient : recipients) subtractCount += recipient.fSubtractFeeFromAmount;
        for (const auto& recipient : privateRecipients) subtractCount += recipient.second;

        const CAmount fee = plan.batches.front().fee;
        const CAmount feePerRecipient = fee / static_cast<CAmount>(subtractCount);
        const CAmount feeRemainder = fee % static_cast<CAmount>(subtractCount);
        bool firstSubtracted = false;
        const auto shareCovered = [&](CAmount amount) {
            const CAmount share = feePerRecipient + (firstSubtracted ? 0 : feeRemainder);
            firstSubtracted = true;
            return amount > share;
        };
        for (const CRecipient& recipient : recipients) {
            if (recipient.fSubtractFeeFromAmount && !shareCovered(recipient.nAmount)) {
                throw std::runtime_error(_(
                    "A recipient amount is too small to cover its share of the transaction fee."));
            }
        }
        for (const auto& recipient : privateRecipients) {
            if (recipient.second && !shareCovered(static_cast<CAmount>(recipient.first.v))) {
                throw std::runtime_error(_(
                    "A recipient amount is too small to cover its share of the transaction fee."));
            }
        }
    }

    // Create and validate every transaction before committing any of them so
    // create-time / fee-mismatch failures cannot leave a partial payment on
    // the network. Commit-time failures can still leave earlier txs broadcast;
    // those are reported via SparkSpendBatchPartialFailure.
    std::vector<PreparedBatch> prepared;
    prepared.reserve(plan.batches.size());

    for (const spark::SingleInputBatch& batch : plan.batches) {
        if (batch.coinIndex >= availableCoins.size()) {
            throw std::runtime_error(_("Unable to select Spark coins for spend."));
        }

        CCoinControl singleCoinControl = coinControl ? *coinControl : CCoinControl();
        singleCoinControl.UnSelectAll();
        singleCoinControl.fAllowOtherInputs = false;
        singleCoinControl.fRequireAllInputs = true;
        singleCoinControl.Select(availableCoins[batch.coinIndex].outpoint);

        std::vector<CRecipient> batchRecipients;
        std::vector<std::pair<spark::OutputCoinData, bool>> batchPrivateRecipients;
        if (plan.batches.size() == 1) {
            batchRecipients = recipients;
            batchPrivateRecipients = privateRecipients;
        } else {
            batchRecipients.reserve(batch.transparentOutputs);
            batchPrivateRecipients.reserve(batch.privateOutputs);
            for (const spark::BatchFragment& fragment : batch.fragments) {
                const RecipientEntry& entry = recipientEntries[fragment.recipientIndex];
                if (entry.isPrivate) {
                    spark::OutputCoinData output = entry.privateOutput;
                    output.v = fragment.amount;
                    batchPrivateRecipients.emplace_back(std::move(output), false);
                } else {
                    batchRecipients.push_back({entry.scriptPubKey, fragment.amount, false});
                }
            }
        }

        PreparedBatch preparedBatch;
        preparedBatch.wtx = wallet.CreateSparkSpendTransaction(
            batchRecipients,
            batchPrivateRecipients,
            preparedBatch.fee,
            &singleCoinControl);

        if (!preparedBatch.wtx.tx || spark::GetSpendInputs(*preparedBatch.wtx.tx) != 1) {
            throw std::runtime_error(_(
                "Unable to create a single-input Spark transaction."));
        }

        if (preparedBatch.fee != batch.fee) {
            throw std::runtime_error(strprintf(
                _("Spark fee estimate did not match the wallet (planned %s, wallet %s)."),
                FormatMoney(batch.fee),
                FormatMoney(preparedBatch.fee)));
        }

        prepared.push_back(std::move(preparedBatch));
    }

    // Reserve the planned coins for the commit phase, so a concurrent spend
    // from this wallet cannot take one of them and turn a later commit failure
    // into a partial payment. This must happen after transaction creation:
    // GetAvailableSparkCoins filters locked coins even when they are selected
    // through coin control. Creation failures above abort before anything is
    // sent, so only the commit loop needs the reservation.
    std::vector<COutPoint> reservedCoins;
    reservedCoins.reserve(plan.batches.size());
    for (const spark::SingleInputBatch& batch : plan.batches) {
        reservedCoins.push_back(availableCoins[batch.coinIndex].outpoint);
    }
    struct ReservedCoins {
        CWallet& wallet;
        const std::vector<COutPoint>& coins;
        ReservedCoins(CWallet& _wallet, const std::vector<COutPoint>& _coins)
            : wallet(_wallet), coins(_coins)
        {
            LOCK(wallet.cs_wallet);
            for (const COutPoint& coin : coins) wallet.LockCoin(coin);
        }
        ~ReservedCoins()
        {
            LOCK(wallet.cs_wallet);
            for (const COutPoint& coin : coins) wallet.UnlockCoin(coin);
        }
    } reservedCoinsGuard(wallet, reservedCoins);

    std::vector<CWalletTx> committedTransactions;
    committedTransactions.reserve(prepared.size());
    totalFee = 0;

    for (PreparedBatch& preparedBatch : prepared) {
        try {
            CommitSparkSpend(wallet, preparedBatch.wtx);
        } catch (const std::exception& e) {
            if (!committedTransactions.empty()) {
                std::vector<uint256> committedTxids;
                committedTxids.reserve(committedTransactions.size());
                for (const CWalletTx& wtx : committedTransactions) {
                    committedTxids.push_back(wtx.GetHash());
                }
                throw SparkSpendBatchPartialFailure(
                    e.what(),
                    std::move(committedTxids),
                    totalFee,
                    prepared.size());
            }
            throw;
        }

        totalFee += preparedBatch.fee;
        committedTransactions.push_back(std::move(preparedBatch.wtx));
    }

    return committedTransactions;
}

} // namespace sparkspendbatch
