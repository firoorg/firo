#include "batchproof_container.h"
#include "ui_interface.h"
#include "spark/state.h"
#include "util.h"

#include <unordered_map>

#include <boost/filesystem.hpp>

extern bool fReindex;

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

void BatchProofContainer::init() {
    tempSparkTransactions.clear();
    tempSparkTxIds.clear();
    tempHistoricalSparkTransactions.clear();
    tempHistoricalSparkTxIds.clear();
    tempSpatsTransactions.clear();
    tempSpatsTxIds.clear();
    if (fCollectProofs)
        WriteRecoveryMarker();
}

void BatchProofContainer::finalize() {
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
        spatsTransactions.insert(
            spatsTransactions.end(),
            tempSpatsTransactions.begin(),
            tempSpatsTransactions.end());
        spatsTxIds.insert(
            spatsTxIds.end(),
            tempSpatsTxIds.begin(),
            tempSpatsTxIds.end());
    }
    tempSparkTransactions.clear();
    tempSparkTxIds.clear();
    tempHistoricalSparkTransactions.clear();
    tempHistoricalSparkTxIds.clear();
    tempSpatsTransactions.clear();
    tempSpatsTxIds.clear();
    fCollectProofs = false;
}

bool BatchProofContainer::verify_pending() {
    bool passed = true;
    if (!fCollectProofs) {
        init();
        passed = batch_spark();
        if (!passed)
            WriteRecoveryMarker();
        else if (!fReindex)
            RemoveRecoveryMarker();
    }
    fCollectProofs = false;
    return passed;
}

void BatchProofContainer::add(const spark::SpendTransaction& tx, const uint256& txHash) {
    tempSparkTransactions.push_back(tx);
    tempSparkTxIds.push_back(txHash);
}

void BatchProofContainer::addHistorical(
    const spark::SpendTransaction& tx, const uint256& txHash) {
    tempHistoricalSparkTransactions.push_back(tx);
    tempHistoricalSparkTxIds.push_back(txHash);
}

void BatchProofContainer::add(const spats::SpendTransaction& tx, const uint256& txHash) {
    tempSpatsTransactions.push_back(tx);
    tempSpatsTxIds.push_back(txHash);
}

void BatchProofContainer::remove(const spark::SpendTransaction& tx) {
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
        // the pending batch changed, so a previous failure verdict no longer applies
        fBatchFailed = false;
    }
}

void BatchProofContainer::remove(const spats::SpendTransaction& tx) {
    bool fBatchChanged = false;
    for (std::size_t i = spatsTransactions.size(); i-- > 0;) {
        if (spatsTransactions[i].getUsedLTags() == tx.getUsedLTags()) {
            spatsTransactions.erase(spatsTransactions.begin() + i);
            spatsTxIds.erase(spatsTxIds.begin() + i);
            fBatchChanged = true;
        }
    }
    if (fBatchChanged) {
        fBatchFailed = false;
    }
}

static std::unordered_map<uint64_t, std::vector<spark::Coin>> LoadSpatsCoverSets(
    spark::CSparkState* sparkState,
    std::vector<spats::SpendTransaction>& txs)
{
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
    std::vector<spark::Coin> coins;
    for (auto& tx : txs) {
        for (uint64_t id : tx.getCoinGroupIds()) {
            if (!cover_sets.count(id)) {
                coins.clear();
                sparkState->GetCoinSet(static_cast<int32_t>(id), coins);
                cover_sets.emplace(id, std::move(coins));
                coins.clear();
            }
            // Reject before verify. Grootle treats the committed size as a suffix.
            if (cover_sets.at(id).size() < tx.getCoverSetSize(id))
                throw std::invalid_argument("Cover set shorter than SPATS proof");
        }
    }
    return cover_sets;
}

bool BatchProofContainer::batch_spark() {
    if (sparkTransactions.empty() && historicalSparkTransactions.empty() && spatsTransactions.empty())
        return true;
    if (fBatchFailed)
        return false;

    LogPrintf("Spark batch verification started.\n");
    uiInterface.UpdateProgressBarLabel("Batch verifying Spark Proofs...");

    spark::CSparkState* sparkState = spark::CSparkState::GetState();
    std::vector<spark::Coin> loadedCoverSet;
    const spark::SpendTransaction::CoverSetProvider coverSetProvider =
        [sparkState, &loadedCoverSet](uint64_t id)
            -> const std::vector<spark::Coin>& {
        loadedCoverSet.clear();
        sparkState->GetCoinSet(static_cast<int32_t>(id), loadedCoverSet);
        return loadedCoverSet;
    };
    auto* params = spark::Params::get_default();

    bool passed = true;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> spatsCoverSets;
    try {
        if (!sparkTransactions.empty()) {
            passed = spark::SpendTransaction::verify(
                params, sparkTransactions, coverSetProvider);
        }
        if (passed && !historicalSparkTransactions.empty()) {
            passed = spark::SpendTransaction::verifyHistorical(
                params, historicalSparkTransactions, coverSetProvider);
        }
        if (passed && !spatsTransactions.empty()) {
            spatsCoverSets = LoadSpatsCoverSets(sparkState, spatsTransactions);
            passed = spats::SpendTransaction::verify(
                params, spatsTransactions, spatsCoverSets);
        }
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
                    params, {sparkTransactions[i]}, coverSetProvider);
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
                    params, {historicalSparkTransactions[i]}, coverSetProvider);
            } catch (const std::exception &) {
                fProofValid = false;
            }
            if (!fProofValid) {
                LogPrintf("Spark batch verification failed for spend transaction %s.\n", historicalSparkTxIds[i].ToString());
            }
        }
        for (std::size_t i = 0; i < spatsTransactions.size(); ++i) {
            bool fProofValid;
            try {
                std::vector<spats::SpendTransaction> one = {spatsTransactions[i]};
                auto coverSets = LoadSpatsCoverSets(sparkState, one);
                fProofValid = spats::SpendTransaction::verify(
                    params, one, coverSets);
            } catch (const std::exception &) {
                fProofValid = false;
            }
            if (!fProofValid) {
                LogPrintf("Spark batch verification failed for spend transaction %s.\n", spatsTxIds[i].ToString());
            }
        }
        LogPrintf("Spark batch verification failed.\n");
        fBatchFailed = true;
        return false;
    }

    LogPrintf("Spark batch verification finished successfully.\n");
    sparkTransactions.clear();
    sparkTxIds.clear();
    historicalSparkTransactions.clear();
    historicalSparkTxIds.clear();
    spatsTransactions.clear();
    spatsTxIds.clear();
    return true;
}
