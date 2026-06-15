#include "batchproof_container.h"
#include "ui_interface.h"
#include "spark/state.h"

#include <stdexcept>
#include <unordered_map>

std::unique_ptr<BatchProofContainer> BatchProofContainer::instance;

namespace
{
struct SparkBatchCoverSetSelection {
    int maxHeight = -1;
};
} // namespace

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

void BatchProofContainer::clear() {
    tempSparkTransactions.clear();
    sparkTransactions.clear();
    fCollectProofs = false;
}

void BatchProofContainer::finalize() {
    if (fCollectProofs) {
        sparkTransactions.insert(sparkTransactions.end(), tempSparkTransactions.begin(), tempSparkTransactions.end());
        tempSparkTransactions.clear();
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

    // Grootle batching verifies each proof against the suffix identified by
    // its own cover-set size, so each group only needs the largest referenced
    // historical set, not the current full group.
    std::unordered_map<uint64_t, SparkBatchCoverSetSelection> cover_set_selections;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
    spark::CSparkState* sparkState = spark::CSparkState::GetState();

    for (auto& itr : sparkTransactions) {
        auto& idAndBlockHashes = itr.getBlockHashes();
        for (const auto& idAndHash : idAndBlockHashes) {
            int cover_set_id = idAndHash.first;
            spark::CSparkState::SparkCoinGroupInfo coinGroup;
            if (!sparkState->GetCoinGroupInfo(cover_set_id, coinGroup))
                throw std::invalid_argument("Spark batch verification missing cover set");
            if (!coinGroup.firstBlock || !coinGroup.lastBlock)
                throw std::invalid_argument("Spark batch verification invalid cover set index");

            CBlockIndex* index = coinGroup.lastBlock;
            while (index && index != coinGroup.firstBlock && index->GetBlockHash() != idAndHash.second)
                index = index->pprev;
            if (!index)
                throw std::invalid_argument("Spark batch verification missing cover set ancestry");

            if (index->GetBlockHash() != idAndHash.second)
                throw std::invalid_argument("Spark batch verification missing cover set block");

            auto& selection = cover_set_selections[idAndHash.first];
            if (index->nHeight > selection.maxHeight)
                selection.maxHeight = index->nHeight;
        }
    }

    for (const auto& selection : cover_set_selections) {
        if (selection.second.maxHeight < 0)
            throw std::invalid_argument("Spark batch verification missing cover set block");

        uint256 blockHash;
        std::vector<unsigned char> setHash;
        std::vector<spark::Coin> cover_set;
        const int nCoins = sparkState->GetCoinSetForSpend(
                &chainActive,
                selection.second.maxHeight,
                static_cast<int>(selection.first),
                blockHash,
                cover_set,
                setHash);
        if (nCoins <= 0 || cover_set.empty())
            throw std::invalid_argument("Spark batch verification empty cover set");

        cover_sets[selection.first] = cover_set;
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
