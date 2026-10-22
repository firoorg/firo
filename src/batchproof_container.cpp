#include "batchproof_container.h"
#include "ui_interface.h"
#include "spark/state.h"
#include "util.h"
#include "validation.h"

#include <boost/filesystem.hpp>
#include <boost/scope_exit.hpp>
#include <unordered_map>

namespace {

using CoverSets = std::unordered_map<int32_t, std::vector<spark::Coin>>;

// Load each deployed state group once, shared by current and historical proofs.
// The snapshot owns the coins, so verification does not access chain state.
CoverSets LoadCoverSets(
    std::vector<spark::SpendTransaction>& transactions,
    std::vector<spark::SpendTransaction>& historicalTransactions)
{
    AssertLockHeld(cs_main);
    CoverSets coverSets;
    for (auto* batch : {&transactions, &historicalTransactions}) {
        for (auto& tx : *batch) {
            for (uint64_t id : tx.getCoinGroupIds()) {
                const int32_t stateId = static_cast<int32_t>(id);
                auto entry = coverSets.try_emplace(stateId);
                if (entry.second) {
                    uint256 blockHash;
                    std::vector<unsigned char> setHash;
                    // Consensus can reference newer coins than the wallet's
                    // confirmation window. Snapshot the whole active group.
                    spark::CSparkState::GetState()->GetCoinSetForSpend(
                        &chainActive, chainActive.Height(), stateId,
                        blockHash, entry.first->second, setHash);
                }
            }
        }
    }
    return coverSets;
}

using SpatsCoverSets = std::unordered_map<uint64_t, std::vector<spark::Coin>>;

// Snapshot each SPATS anonymity set once. Grootle treats the committed size as a
// suffix, so a set shorter than the proof is rejected before verification.
SpatsCoverSets LoadSpatsCoverSets(std::vector<spats::SpendTransaction>& transactions)
{
    AssertLockHeld(cs_main);
    SpatsCoverSets coverSets;
    for (auto& tx : transactions) {
        for (uint64_t id : tx.getCoinGroupIds()) {
            auto entry = coverSets.try_emplace(id);
            if (entry.second) {
                uint256 blockHash;
                std::vector<unsigned char> setHash;
                spark::CSparkState::GetState()->GetCoinSetForSpend(
                    &chainActive, chainActive.Height(), static_cast<int32_t>(id),
                    blockHash, entry.first->second, setHash);
            }
            if (coverSets.at(id).size() < tx.getCoverSetSize(id))
                throw std::invalid_argument("Cover set shorter than SPATS proof");
        }
    }
    return coverSets;
}

void LogFailedSpats(
    const std::vector<spats::SpendTransaction>& transactions,
    const std::vector<uint256>& txIds,
    const SpatsCoverSets* coverSets)
{
    auto* params = spark::Params::get_default();
    for (std::size_t i = 0; i < transactions.size(); ++i) {
        bool fProofValid = false;
        try {
            std::vector<spats::SpendTransaction> one{transactions[i]};
            if (coverSets) {
                fProofValid = spats::SpendTransaction::verify(params, one, *coverSets);
            } else {
                LOCK(cs_main);
                const auto oneSets = LoadSpatsCoverSets(one);
                fProofValid = spats::SpendTransaction::verify(params, one, oneSets);
            }
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception&) {
            fProofValid = false;
        }
        if (!fProofValid)
            LogPrintf("Spark batch verification failed for spend transaction %s.\n", txIds[i].ToString());
    }
}

bool VerifySparkBatch(
    const std::vector<spark::SpendTransaction>& sparkTransactions,
    const std::vector<uint256>& sparkTxIds,
    const std::vector<spark::SpendTransaction>& historicalSparkTransactions,
    const std::vector<uint256>& historicalSparkTxIds,
    const CoverSets& coverSets,
    const std::vector<spats::SpendTransaction>& spatsTransactions,
    const std::vector<uint256>& spatsTxIds,
    const SpatsCoverSets* spatsCoverSets)
{
    if (sparkTransactions.empty() && historicalSparkTransactions.empty() && spatsTransactions.empty())
        return true;

    LogPrintf("Spark batch verification started.\n");

    const spark::SpendTransaction::CoverSetProvider coverSetProvider =
        [&coverSets](uint64_t id) -> const std::vector<spark::Coin>& {
            return coverSets.at(static_cast<int32_t>(id));
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
        if (passed && !spatsTransactions.empty()) {
            if (!spatsCoverSets)
                throw std::invalid_argument("Cover set shorter than SPATS proof");
            passed = spats::SpendTransaction::verify(
                params, spatsTransactions, *spatsCoverSets);
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
                    params, {sparkTransactions[i]}, coverSetProvider);
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
                    params, {historicalSparkTransactions[i]}, coverSetProvider);
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception &) {
                fProofValid = false;
            }
            if (!fProofValid) {
                LogPrintf("Spark batch verification failed for spend transaction %s.\n", historicalSparkTxIds[i].ToString());
            }
        }
        LogFailedSpats(spatsTransactions, spatsTxIds, spatsCoverSets);
        LogPrintf("Spark batch verification failed.\n");
        return false;
    }

    LogPrintf("Spark batch verification finished successfully.\n");
    return true;
}


} // namespace

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


BatchProofContainer* BatchProofContainer::get_instance()
{
    static BatchProofContainer instance;
    return &instance;
}

void BatchProofContainer::init(Mode nextMode)
{
    LOCK(cs_main);
    tempSparkTransactions.clear();
    tempSparkTxIds.clear();
    tempHistoricalSparkTransactions.clear();
    tempHistoricalSparkTxIds.clear();
    tempSpatsTransactions.clear();
    tempSpatsTxIds.clear();
    mode = nextMode;
    if (mode == Mode::Deferred)
        WriteRecoveryMarker();
}

void BatchProofContainer::finalize()
{
    LOCK(cs_main);
    assert(mode != Mode::Block);
    if (mode == Mode::Deferred) {
        const auto size = sparkTransactions.size();
        const auto historicalSize = historicalSparkTransactions.size();
        const auto spatsSize = spatsTransactions.size();
        try {
            sparkTransactions.insert(sparkTransactions.end(), tempSparkTransactions.begin(), tempSparkTransactions.end());
            sparkTxIds.insert(sparkTxIds.end(), tempSparkTxIds.begin(), tempSparkTxIds.end());
            historicalSparkTransactions.insert(historicalSparkTransactions.end(), tempHistoricalSparkTransactions.begin(), tempHistoricalSparkTransactions.end());
            historicalSparkTxIds.insert(historicalSparkTxIds.end(), tempHistoricalSparkTxIds.begin(), tempHistoricalSparkTxIds.end());
            spatsTransactions.insert(spatsTransactions.end(), tempSpatsTransactions.begin(), tempSpatsTransactions.end());
            spatsTxIds.insert(spatsTxIds.end(), tempSpatsTxIds.begin(), tempSpatsTxIds.end());
        } catch (...) {
            // Keep proof/txid pairs aligned; temps still own the whole block.
            sparkTransactions.erase(sparkTransactions.begin() + size, sparkTransactions.end());
            sparkTxIds.erase(sparkTxIds.begin() + size, sparkTxIds.end());
            historicalSparkTransactions.erase(historicalSparkTransactions.begin() + historicalSize, historicalSparkTransactions.end());
            historicalSparkTxIds.erase(historicalSparkTxIds.begin() + historicalSize, historicalSparkTxIds.end());
            spatsTransactions.erase(spatsTransactions.begin() + spatsSize, spatsTransactions.end());
            spatsTxIds.erase(spatsTxIds.begin() + spatsSize, spatsTxIds.end());
            throw;
        }
        ++generation;
    }
    init();
}

bool BatchProofContainer::is_deferred() const
{
    LOCK(cs_main);
    return mode == Mode::Deferred;
}

bool BatchProofContainer::verify_block_batch()
{
    AssertLockHeld(cs_main);
    if (mode != Mode::Block)
        return true;

    const auto coverSets = LoadCoverSets(tempSparkTransactions, tempHistoricalSparkTransactions);
    SpatsCoverSets spatsCoverSets;
    const SpatsCoverSets* spatsCoverPtr = nullptr;
    try {
        if (!tempSpatsTransactions.empty()) {
            spatsCoverSets = LoadSpatsCoverSets(tempSpatsTransactions);
            spatsCoverPtr = &spatsCoverSets;
        }
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        spatsCoverPtr = nullptr;
    }
    const bool passed = VerifySparkBatch(
        tempSparkTransactions, tempSparkTxIds,
        tempHistoricalSparkTransactions, tempHistoricalSparkTxIds, coverSets,
        tempSpatsTransactions, tempSpatsTxIds, spatsCoverPtr);
    init();
    return passed;
}

bool BatchProofContainer::verify_pending()
{
    AssertLockNotHeld(cs_main);
    LOCK(cs_verify);
    for (;;) {
        std::vector<spark::SpendTransaction> transactions, historicalTransactions;
        std::vector<uint256> txIds, historicalTxIds;
        std::vector<spats::SpendTransaction> spatsTxs;
        std::vector<uint256> spatsIds;
        CoverSets coverSets;
        SpatsCoverSets spatsCoverSets;
        const SpatsCoverSets* spatsCoverPtr = nullptr;
        uint64_t snapshotGeneration;
        const CBlockIndex* snapshotTip;
        {
            LOCK(cs_main);
            if (mode != Mode::Disabled)
                return true;
            if (fBatchFailed)
                return false;
            if (sparkTransactions.empty() && historicalSparkTransactions.empty() && spatsTransactions.empty()) {
                if (!fReindex)
                    RemoveRecoveryMarker();
                return true;
            }
            // Retain the canonical proofs. Disconnects can remove them, and an
            // exception cannot destroy the only copy of an unchecked batch.
            transactions = sparkTransactions;
            txIds = sparkTxIds;
            historicalTransactions = historicalSparkTransactions;
            historicalTxIds = historicalSparkTxIds;
            spatsTxs = spatsTransactions;
            spatsIds = spatsTxIds;
            coverSets = LoadCoverSets(transactions, historicalTransactions);
            try {
                if (!spatsTxs.empty()) {
                    spatsCoverSets = LoadSpatsCoverSets(spatsTxs);
                    spatsCoverPtr = &spatsCoverSets;
                }
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception&) {
                spatsCoverPtr = nullptr;
            }
            snapshotGeneration = generation;
            snapshotTip = chainActive.Tip();
        }

        // Only deferred batches need a global progress label. cs_verify keeps
        // their notifications ordered while recent blocks verify independently.
        BOOST_SCOPE_EXIT(void) {
            try {
                uiInterface.UpdateProgressBarLabel("");
            } catch (...) {
                // A UI notification must not interrupt proof cleanup or unwinding.
            }
        } BOOST_SCOPE_EXIT_END
        uiInterface.UpdateProgressBarLabel(_("Batch verifying Spark Proofs..."));

        const bool passed = VerifySparkBatch(
            transactions, txIds, historicalTransactions, historicalTxIds, coverSets,
            spatsTxs, spatsIds, spatsCoverPtr);

        LOCK(cs_main);
        if (generation != snapshotGeneration || chainActive.Tip() != snapshotTip)
            continue;
        if (!passed) {
            fBatchFailed = true;
            WriteRecoveryMarker();
            return false;
        }
        sparkTransactions.clear();
        sparkTxIds.clear();
        historicalSparkTransactions.clear();
        historicalSparkTxIds.clear();
        spatsTransactions.clear();
        spatsTxIds.clear();
        ++generation;
        if (!fReindex)
            RemoveRecoveryMarker();
        return true;
    }
}

bool BatchProofContainer::add(const spark::SpendTransaction& tx, const uint256& txHash)
{
    LOCK(cs_main);
    if (mode == Mode::Disabled)
        return false;
    tempSparkTxIds.push_back(txHash);
    try {
        tempSparkTransactions.push_back(tx);
    } catch (...) {
        tempSparkTxIds.pop_back();
        throw;
    }
    return true;
}

bool BatchProofContainer::addHistorical(const spark::SpendTransaction& tx, const uint256& txHash)
{
    LOCK(cs_main);
    if (mode == Mode::Disabled)
        return false;
    tempHistoricalSparkTxIds.push_back(txHash);
    try {
        tempHistoricalSparkTransactions.push_back(tx);
    } catch (...) {
        tempHistoricalSparkTxIds.pop_back();
        throw;
    }
    return true;
}

void BatchProofContainer::remove(const spark::SpendTransaction& tx)
{
    LOCK(cs_main);
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
        ++generation;
        fBatchFailed = false;
    }
}

bool BatchProofContainer::add(const spats::SpendTransaction& tx, const uint256& txHash)
{
    LOCK(cs_main);
    if (mode == Mode::Disabled)
        return false;
    tempSpatsTxIds.push_back(txHash);
    try {
        tempSpatsTransactions.push_back(tx);
    } catch (...) {
        tempSpatsTxIds.pop_back();
        throw;
    }
    return true;
}

void BatchProofContainer::remove(const spats::SpendTransaction& tx)
{
    LOCK(cs_main);
    bool fBatchChanged = false;
    for (std::size_t i = spatsTransactions.size(); i-- > 0;) {
        if (spatsTransactions[i].getUsedLTags() == tx.getUsedLTags()) {
            spatsTransactions.erase(spatsTransactions.begin() + i);
            spatsTxIds.erase(spatsTxIds.begin() + i);
            fBatchChanged = true;
        }
    }
    if (fBatchChanged) {
        ++generation;
        fBatchFailed = false;
    }
}
