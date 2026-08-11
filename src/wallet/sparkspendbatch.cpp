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
#include "utilmoneystr.h"
#include "validation.h"
#include "wallet/sparkbatchplanner.h"
#include "wallet/walletexcept.h"

#include <stdexcept>
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

CAmount EstimateSingleInputSparkFee(size_t privateOutputs, size_t transparentOutputs)
{
    const unsigned int estimatedSize =
        spark::EstimateSingleInputSparkSize(privateOutputs, transparentOutputs);

    return std::max(
        payTxFee.GetFeePerK(),
        CWallet::GetMinimumFee(estimatedSize, nTxConfirmTarget, mempool));
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
    if (!wallet.CommitTransaction(wtx, reserveKey, g_connman.get(), state)) {
        throw std::runtime_error(state.GetRejectReason());
    }
}

} // namespace

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
        plannerRecipients.push_back({recipient.nAmount, false, 1});
    }
    for (const auto& recipient : privateRecipients) {
        const CAmount amount = static_cast<CAmount>(recipient.first.v);
        RecipientEntry entry;
        entry.isPrivate = true;
        entry.privateOutput = recipient.first;
        entry.subtractFee = recipient.second;
        recipientEntries.push_back(entry);
        plannerRecipients.push_back({amount, true, 1});
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

        const auto& consensus = Params().GetConsensus();
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

    std::vector<CWalletTx> committedTransactions;
    committedTransactions.reserve(plan.batches.size());
    totalFee = 0;

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

        CAmount fee = 0;
        CWalletTx walletTransaction = wallet.CreateSparkSpendTransaction(
            batchRecipients,
            batchPrivateRecipients,
            fee,
            &singleCoinControl);

        if (!walletTransaction.tx || spark::GetSpendInputs(*walletTransaction.tx) != 1) {
            throw std::runtime_error(_(
                "Unable to create a single-input Spark transaction."));
        }

        if (fee != batch.fee) {
            throw std::runtime_error(strprintf(
                _("Spark fee estimate did not match the wallet (planned %s, wallet %s)."),
                FormatMoney(batch.fee),
                FormatMoney(fee)));
        }

        CommitSparkSpend(wallet, walletTransaction);
        totalFee += fee;
        committedTransactions.push_back(std::move(walletTransaction));
    }

    return committedTransactions;
}

} // namespace sparkspendbatch
