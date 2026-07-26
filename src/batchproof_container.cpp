#include "batchproof_container.h"
#include "ui_interface.h"
#include "spark/state.h"

std::unique_ptr<BatchProofContainer> BatchProofContainer::instance;

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
}

void BatchProofContainer::finalize() {
    if (fCollectProofs) {
        sparkTransactions.insert(sparkTransactions.end(), tempSparkTransactions.begin(), tempSparkTransactions.end());
        sparkTxIds.insert(sparkTxIds.end(), tempSparkTxIds.begin(), tempSparkTxIds.end());
    }
    tempSparkTransactions.clear();
    tempSparkTxIds.clear();
    fCollectProofs = false;
}

bool BatchProofContainer::verify_pending() {
    tempSparkTransactions.clear();
    fCollectProofs = false;
    return batch_spark();
}

void BatchProofContainer::add(const spark::SpendTransaction& tx, const uint256& txHash) {
    tempSparkTransactions.push_back(tx);
    tempSparkTxIds.push_back(txHash);
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
    if (fBatchChanged) {
        // the pending batch changed, so a previous failure verdict no longer applies
        fBatchFailed = false;
    }
}

bool BatchProofContainer::batch_spark() {
    if (sparkTransactions.empty())
        return true;
    if (fBatchFailed)
        return false;

    LogPrintf("Spark batch verification started.\n");
    uiInterface.UpdateProgressBarLabel("Batch verifying Spark Proofs...");

    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
    spark::CSparkState* sparkState = spark::CSparkState::GetState();

    for (auto& itr : sparkTransactions) {
        auto& idAndBlockHashes = itr.getBlockHashes();
        for (const auto& idAndHash : idAndBlockHashes) {
            int cover_set_id = idAndHash.first;
            if (!cover_sets.count(cover_set_id)) {
                std::vector<spark::Coin> cover_set;
                sparkState->GetCoinSet(cover_set_id, cover_set);
                cover_sets[cover_set_id] = cover_set;
            }
        }
    }
    auto* params = spark::Params::get_default();

    bool passed;
    try {
        passed = spark::SpendTransaction::verify(params, sparkTransactions, cover_sets);
    } catch (const std::exception &) {
        passed = false;
    }

    if (!passed) {
        // Re-verify the retained proofs individually so the operator can see
        // exactly which spends are invalid without a diagnostic reindex.
        for (std::size_t i = 0; i < sparkTransactions.size(); ++i) {
            bool fProofValid;
            try {
                fProofValid = spark::SpendTransaction::verify(sparkTransactions[i], cover_sets);
            } catch (const std::exception &) {
                fProofValid = false;
            }
            if (!fProofValid) {
                LogPrintf("Spark batch verification failed for spend transaction %s.\n", sparkTxIds[i].ToString());
            }
        }
        LogPrintf("Spark batch verification failed.\n");
        fBatchFailed = true;
        return false;
    }

    LogPrintf("Spark batch verification finished successfully.\n");
    sparkTransactions.clear();
    sparkTxIds.clear();
    return true;
}
