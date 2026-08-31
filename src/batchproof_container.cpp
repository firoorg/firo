#include "batchproof_container.h"
#include "ui_interface.h"
#include "spark/state.h"
#include "util.h"

#include <boost/filesystem.hpp>
#include <set>
#include <unordered_map>

namespace {

bool VerifySparkBatch(
    const std::vector<spark::SpendTransaction>& sparkTransactions,
    const std::vector<uint256>& sparkTxIds,
    const std::vector<spark::SpendTransaction>& historicalSparkTransactions,
    const std::vector<uint256>& historicalSparkTxIds,
    const std::unordered_map<uint64_t, std::vector<spark::Coin>>& coverSets)
{
    if (sparkTransactions.empty() && historicalSparkTransactions.empty())
        return true;

    LogPrintf("Spark batch verification started.\n");
    uiInterface.UpdateProgressBarLabel("Batch verifying Spark Proofs...");

    auto* params = spark::Params::get_default();

    bool passed = true;
    try {
        if (!sparkTransactions.empty()) {
            passed = spark::SpendTransaction::verify(
                params, sparkTransactions, coverSets);
        }
        if (passed && !historicalSparkTransactions.empty()) {
            passed = spark::SpendTransaction::verifyHistorical(
                params, historicalSparkTransactions, coverSets);
        }
    } catch (const std::bad_alloc &) {
        throw;
    } catch (const std::exception &) {
        passed = false;
    }

    if (!passed) {
        // Re-verify the batch members individually so the operator can see
        // exactly which spends are invalid without a diagnostic reindex.
        for (std::size_t i = 0; i < sparkTransactions.size(); ++i) {
            bool fProofValid;
            try {
                fProofValid = spark::SpendTransaction::verify(
                    params, {sparkTransactions[i]}, coverSets);
            } catch (const std::bad_alloc &) {
                throw;
            } catch (const std::exception &) {
                fProofValid = false;
            }
            if (!fProofValid) {
                LogPrintf("Spark batch verification failed for spend transaction %s.\n", sparkTxIds[i].ToString());
            }
        }
        for (std::size_t i = 0; i < historicalSparkTransactions.size(); ++i) {
            bool fProofValid;
            try {
                fProofValid = spark::SpendTransaction::verifyHistorical(
                    params, {historicalSparkTransactions[i]}, coverSets);
            } catch (const std::bad_alloc &) {
                throw;
            } catch (const std::exception &) {
                fProofValid = false;
            }
            if (!fProofValid) {
                LogPrintf("Spark batch verification failed for spend transaction %s.\n", historicalSparkTxIds[i].ToString());
            }
        }
        LogPrintf("Spark batch verification failed.\n");
        return false;
    }

    LogPrintf("Spark batch verification finished successfully.\n");
    return true;
}

} // namespace

std::unique_ptr<BatchProofContainer> BatchProofContainer::instance;

static boost::filesystem::path RecoveryMarkerPath()
{
    return GetDataDir() / "sparkbatchfailed";
}

bool BatchProofContainer::HasRecoveryMarker()
{
    return boost::filesystem::exists(RecoveryMarkerPath());
}

void BatchProofContainer::RemoveRecoveryMarker()
{
    boost::filesystem::remove(RecoveryMarkerPath());
}

BatchProofContainer* BatchProofContainer::get_instance() {
    if (instance) {
        return instance.get();
    } else {
        instance.reset(new BatchProofContainer());
        return instance.get();
    }
}

void BatchProofContainer::init(bool collectProofs) {
    LOCK(cs_batch);
    sparkTransactions.clear();
    sparkTxIds.clear();
    historicalSparkTransactions.clear();
    historicalSparkTxIds.clear();
    fCollectProofs = collectProofs;
}

void BatchProofContainer::abort() {
    init();
}

void BatchProofContainer::finalize() {
    LOCK(cs_batch);
    fCollectProofs = false;
}

bool BatchProofContainer::verify_pending() {
    std::vector<spark::SpendTransaction> snapshotTransactions;
    std::vector<uint256> snapshotTxIds;
    std::vector<spark::SpendTransaction> snapshotHistoricalTransactions;
    std::vector<uint256> snapshotHistoricalTxIds;
    {
        LOCK(cs_batch);
        if (fCollectProofs)
            return true;

        snapshotTransactions.swap(sparkTransactions);
        snapshotTxIds.swap(sparkTxIds);
        snapshotHistoricalTransactions.swap(historicalSparkTransactions);
        snapshotHistoricalTxIds.swap(historicalSparkTxIds);
    }

    std::set<uint64_t> coverSetIds;
    for (auto& tx : snapshotTransactions) {
        for (uint64_t id : tx.getCoinGroupIds())
            coverSetIds.insert(id);
    }
    for (auto& tx : snapshotHistoricalTransactions) {
        for (uint64_t id : tx.getCoinGroupIds())
            coverSetIds.insert(id);
    }
    std::unordered_map<uint64_t, std::vector<spark::Coin>> coverSets;
    spark::CSparkState* sparkState = spark::CSparkState::GetState();
    for (uint64_t id : coverSetIds) {
        std::vector<spark::Coin> coins;
        sparkState->GetCoinSet(static_cast<int32_t>(id), coins);
        coverSets.emplace(id, std::move(coins));
    }

    return VerifySparkBatch(
        snapshotTransactions,
        snapshotTxIds,
        snapshotHistoricalTransactions,
        snapshotHistoricalTxIds,
        coverSets);
}

bool BatchProofContainer::add(const spark::SpendTransaction& tx, const uint256& txHash) {
    LOCK(cs_batch);
    if (!fCollectProofs)
        return false;
    sparkTransactions.push_back(tx);
    sparkTxIds.push_back(txHash);
    return true;
}

bool BatchProofContainer::addHistorical(
    const spark::SpendTransaction& tx, const uint256& txHash) {
    LOCK(cs_batch);
    if (!fCollectProofs)
        return false;
    historicalSparkTransactions.push_back(tx);
    historicalSparkTxIds.push_back(txHash);
    return true;
}
