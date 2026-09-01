#include "batchproof_container.h"
#include "ui_interface.h"
#include "spark/state.h"
#include "util.h"

#include <boost/filesystem.hpp>
#include <iterator>
#include <set>
#include <unordered_map>

extern bool fReindex;

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
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception &) {
        passed = false;
    }

    if (!passed) {
        // Re-verify the retained proofs individually so the operator can see
        // exactly which spends are invalid without a diagnostic reindex.
        for (std::size_t i = 0; i < sparkTransactions.size(); ++i) {
            bool fProofValid;
            try {
                fProofValid = spark::SpendTransaction::verify(
                    params, {sparkTransactions[i]}, coverSets);
            } catch (const std::bad_alloc&) {
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
            } catch (const std::bad_alloc&) {
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

bool VerifySparkBatchSnapshot(
    std::vector<spark::SpendTransaction>& sparkTransactions,
    const std::vector<uint256>& sparkTxIds,
    std::vector<spark::SpendTransaction>& historicalSparkTransactions,
    const std::vector<uint256>& historicalSparkTxIds)
{
    if (sparkTransactions.empty() && historicalSparkTransactions.empty())
        return true;

    std::set<uint64_t> coverSetIds;
    for (auto& tx : sparkTransactions) {
        for (uint64_t id : tx.getCoinGroupIds())
            coverSetIds.insert(id);
    }
    for (auto& tx : historicalSparkTransactions) {
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
        sparkTransactions,
        sparkTxIds,
        historicalSparkTransactions,
        historicalSparkTxIds,
        coverSets);
}

} // namespace

std::unique_ptr<BatchProofContainer> BatchProofContainer::instance;

static boost::filesystem::path RecoveryMarkerPath()
{
    return GetDataDir() / "sparkbatchfailed";
}

static void WriteRecoveryMarker()
{
    const auto path = RecoveryMarkerPath();
    if (boost::filesystem::exists(path))
        return;
    FILE* file = fopen(path.string().c_str(), "wb");
    if (file)
        fclose(file);
    else
        LogPrintf("Failed to write Spark batch recovery marker\n");
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

void BatchProofContainer::init(bool collectProofs, bool fDeferredBatch) {
    LOCK(cs_batch);
    tempSparkTransactions.clear();
    tempSparkTxIds.clear();
    tempHistoricalSparkTransactions.clear();
    tempHistoricalSparkTxIds.clear();
    fCollectProofs = collectProofs;
    if (fCollectProofs && fDeferredBatch)
        WriteRecoveryMarker();
}

void BatchProofContainer::finalize() {
    LOCK(cs_batch);
    if (fCollectProofs) {
        sparkTransactions.insert(sparkTransactions.end(), tempSparkTransactions.begin(), tempSparkTransactions.end());
        sparkTxIds.insert(sparkTxIds.end(), tempSparkTxIds.begin(), tempSparkTxIds.end());
        historicalSparkTransactions.insert(
            historicalSparkTransactions.end(),
            tempHistoricalSparkTransactions.begin(),
            tempHistoricalSparkTransactions.end());
        historicalSparkTxIds.insert(
            historicalSparkTxIds.end(),
            tempHistoricalSparkTxIds.begin(),
            tempHistoricalSparkTxIds.end());
    }
    tempSparkTransactions.clear();
    tempSparkTxIds.clear();
    tempHistoricalSparkTransactions.clear();
    tempHistoricalSparkTxIds.clear();
    fCollectProofs = false;
}

void BatchProofContainer::discard_temps()
{
    LOCK(cs_batch);
    tempSparkTransactions.clear();
    tempSparkTxIds.clear();
    tempHistoricalSparkTransactions.clear();
    tempHistoricalSparkTxIds.clear();
    fCollectProofs = false;
}

bool BatchProofContainer::verify_block_batch()
{
    std::vector<spark::SpendTransaction> snapshotTransactions;
    std::vector<uint256> snapshotTxIds;
    std::vector<spark::SpendTransaction> snapshotHistoricalTransactions;
    std::vector<uint256> snapshotHistoricalTxIds;
    {
        LOCK(cs_batch);
        if (tempSparkTransactions.empty() && tempHistoricalSparkTransactions.empty()) {
            fCollectProofs = false;
            return true;
        }

        snapshotTransactions.swap(tempSparkTransactions);
        snapshotTxIds.swap(tempSparkTxIds);
        snapshotHistoricalTransactions.swap(tempHistoricalSparkTransactions);
        snapshotHistoricalTxIds.swap(tempHistoricalSparkTxIds);
        fCollectProofs = false;
    }

    return VerifySparkBatchSnapshot(
        snapshotTransactions,
        snapshotTxIds,
        snapshotHistoricalTransactions,
        snapshotHistoricalTxIds);
}

bool BatchProofContainer::verify_pending() {
    {
        LOCK(cs_batch);
        if (fCollectProofs) {
            return true;
        }
    }

    while (true) {
        std::vector<spark::SpendTransaction> snapshotTransactions;
        std::vector<uint256> snapshotTxIds;
        std::vector<spark::SpendTransaction> snapshotHistoricalTransactions;
        std::vector<uint256> snapshotHistoricalTxIds;
        {
            LOCK(cs_batch);
            init();
            if (fBatchFailed) {
                fCollectProofs = false;
                return false;
            }
            if (sparkTransactions.empty() && historicalSparkTransactions.empty()) {
                fCollectProofs = false;
                return true;
            }

            snapshotTransactions.swap(sparkTransactions);
            snapshotTxIds.swap(sparkTxIds);
            snapshotHistoricalTransactions.swap(historicalSparkTransactions);
            snapshotHistoricalTxIds.swap(historicalSparkTxIds);
        }

        const bool passed = VerifySparkBatchSnapshot(
            snapshotTransactions,
            snapshotTxIds,
            snapshotHistoricalTransactions,
            snapshotHistoricalTxIds);

        LOCK(cs_batch);
        if (!sparkTransactions.empty() || !historicalSparkTransactions.empty()) {
            sparkTransactions.insert(
                sparkTransactions.end(),
                std::make_move_iterator(snapshotTransactions.begin()),
                std::make_move_iterator(snapshotTransactions.end()));
            sparkTxIds.insert(
                sparkTxIds.end(),
                std::make_move_iterator(snapshotTxIds.begin()),
                std::make_move_iterator(snapshotTxIds.end()));
            historicalSparkTransactions.insert(
                historicalSparkTransactions.end(),
                std::make_move_iterator(snapshotHistoricalTransactions.begin()),
                std::make_move_iterator(snapshotHistoricalTransactions.end()));
            historicalSparkTxIds.insert(
                historicalSparkTxIds.end(),
                std::make_move_iterator(snapshotHistoricalTxIds.begin()),
                std::make_move_iterator(snapshotHistoricalTxIds.end()));
            continue;
        }

        fCollectProofs = false;
        if (passed) {
            if (!fReindex)
                RemoveRecoveryMarker();
            return true;
        }

        sparkTransactions.swap(snapshotTransactions);
        sparkTxIds.swap(snapshotTxIds);
        historicalSparkTransactions.swap(snapshotHistoricalTransactions);
        historicalSparkTxIds.swap(snapshotHistoricalTxIds);
        WriteRecoveryMarker();
        fBatchFailed = true;
        return false;
    }
}

bool BatchProofContainer::add(const spark::SpendTransaction& tx, const uint256& txHash) {
    LOCK(cs_batch);
    if (!fCollectProofs)
        return false;
    tempSparkTransactions.push_back(tx);
    tempSparkTxIds.push_back(txHash);
    return true;
}

bool BatchProofContainer::addHistorical(
    const spark::SpendTransaction& tx, const uint256& txHash) {
    LOCK(cs_batch);
    if (!fCollectProofs)
        return false;
    tempHistoricalSparkTransactions.push_back(tx);
    tempHistoricalSparkTxIds.push_back(txHash);
    return true;
}

void BatchProofContainer::remove(const spark::SpendTransaction& tx) {
    LOCK(cs_batch);
    bool fBatchChanged = false;
    for (std::size_t i = sparkTransactions.size(); i-- > 0;) {
        if (sparkTransactions[i].getUsedLTags() == tx.getUsedLTags()) {
            sparkTransactions.erase(sparkTransactions.begin() + i);
            sparkTxIds.erase(sparkTxIds.begin() + i);
            fBatchChanged = true;
        }
    }
    for (std::size_t i = historicalSparkTransactions.size(); i-- > 0;) {
        if (historicalSparkTransactions[i].getUsedLTags() == tx.getUsedLTags()) {
            historicalSparkTransactions.erase(historicalSparkTransactions.begin() + i);
            historicalSparkTxIds.erase(historicalSparkTxIds.begin() + i);
            fBatchChanged = true;
        }
    }
    if (fBatchChanged) {
        fBatchFailed = false;
    }
}
