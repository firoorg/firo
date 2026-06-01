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
}

void BatchProofContainer::finalize() {
    if (fCollectProofs) {
        sparkTransactions.insert(sparkTransactions.end(), tempSparkTransactions.begin(), tempSparkTransactions.end());
    }
    fCollectProofs = false;
}

void BatchProofContainer::verify() {
    if (!fCollectProofs) {
        batch_spark();
    }
    fCollectProofs = false;
}

void BatchProofContainer::add(const spark::SpendTransaction& tx) {
    tempSparkTransactions.push_back(tx);
}

void BatchProofContainer::remove(const spark::SpendTransaction& tx) {
    sparkTransactions.erase(std::remove_if(sparkTransactions.begin(),
                                           sparkTransactions.end(),
                                  [tx](spark::SpendTransaction& transaction){return transaction.getUsedLTags() == tx.getUsedLTags();}),
                            sparkTransactions.end());
}

void BatchProofContainer::batch_spark() {
    if (!sparkTransactions.empty()){
        LogPrintf("Spark batch verification started.\n");
        uiInterface.UpdateProgressBarLabel("Batch verifying Spark Proofs...");
    } else {
        return;
    }

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
        LogPrintf("Spark batch verification failed.");
        throw std::invalid_argument("Spark batch verification failed, please run Firo with -reindex -batching=0");
    }

    if (!sparkTransactions.empty())
        LogPrintf("Spark batch verification finished successfully.\n");
    sparkTransactions.clear();
}