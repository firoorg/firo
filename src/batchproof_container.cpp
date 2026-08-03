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
    abort();
}

void BatchProofContainer::abort() {
    tempSparkTransactions.clear();
    tempHistoricalSparkTransactions.clear();
    sparkTransactions.clear();
    historicalSparkTransactions.clear();
    fCollectProofs = false;
}

void BatchProofContainer::finalize() {
    if (fCollectProofs) {
        sparkTransactions.insert(sparkTransactions.end(), tempSparkTransactions.begin(), tempSparkTransactions.end());
        historicalSparkTransactions.insert(
            historicalSparkTransactions.end(),
            tempHistoricalSparkTransactions.begin(),
            tempHistoricalSparkTransactions.end());
    }
    fCollectProofs = false;
}

void BatchProofContainer::verify() {
    try {
        if (!fCollectProofs) {
            batch_spark();
        }
        fCollectProofs = false;
    } catch (...) {
        abort();
        throw;
    }
}

void BatchProofContainer::add(const spark::SpendTransaction& tx) {
    tempSparkTransactions.push_back(tx);
}

void BatchProofContainer::addHistorical(
    const spark::SpendTransaction& tx) {
    tempHistoricalSparkTransactions.push_back(tx);
}

void BatchProofContainer::remove(const spark::SpendTransaction& tx) {
    const auto hasSameTags = [&tx](spark::SpendTransaction& transaction) {
        return transaction.getUsedLTags() == tx.getUsedLTags();
    };
    sparkTransactions.erase(
        std::remove_if(sparkTransactions.begin(), sparkTransactions.end(), hasSameTags),
        sparkTransactions.end());
    historicalSparkTransactions.erase(
        std::remove_if(
            historicalSparkTransactions.begin(),
            historicalSparkTransactions.end(),
            hasSameTags),
        historicalSparkTransactions.end());
}

void BatchProofContainer::batch_spark() {
    if (!sparkTransactions.empty() || !historicalSparkTransactions.empty()){
        LogPrintf("Spark batch verification started.\n");
        uiInterface.UpdateProgressBarLabel("Batch verifying Spark Proofs...");
    } else {
        return;
    }

    spark::CSparkState* sparkState = spark::CSparkState::GetState();
    std::vector<spark::Coin> loadedCoverSet;
    const spark::SpendTransaction::CoverSetProvider coverSetProvider =
        [sparkState, &loadedCoverSet](uint64_t wireId)
            -> const std::vector<spark::Coin>& {
        loadedCoverSet.clear();
        sparkState->GetCoinSet(
            static_cast<int>(wireId), loadedCoverSet);
        return loadedCoverSet;
    };
    auto* params = spark::Params::get_default();

    bool passed = true;
    try {
        if (!sparkTransactions.empty()) {
            passed = spark::SpendTransaction::verify(
                params, sparkTransactions, coverSetProvider);
        }
        if (passed && !historicalSparkTransactions.empty()) {
            passed = spark::SpendTransaction::verifyHistorical(
                params, historicalSparkTransactions, coverSetProvider);
        }
    } catch (const std::bad_alloc &) {
        throw;
    } catch (const std::exception &) {
        passed = false;
    }

    // A failed block must not poison later block validation with retained
    // proofs. Successful per-block verification also leaves no cross-block
    // proof state behind.
    sparkTransactions.clear();
    historicalSparkTransactions.clear();

    if (!passed) {
        LogPrintf("Spark batch verification failed.");
        throw std::invalid_argument("Spark batch verification failed");
    }

    LogPrintf("Spark batch verification finished successfully.\n");
}
