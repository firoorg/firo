#ifndef FIRO_BATCHPROOF_CONTAINER_H
#define FIRO_BATCHPROOF_CONTAINER_H

#include <memory>
#include "chain.h"
#include "libspark/spend_transaction.h"
#include "sync.h"

extern CChain chainActive;

class BatchProofContainer {
public:
    static BatchProofContainer* get_instance();

    void init(bool collectProofs = false, bool fDeferredBatch = true);

    void finalize();

    /** Drop in-flight per-block temps without merging into the deferred batch. */
    void discard_temps();

    /**
     * Verify Spark proofs collected for the current block only. Clears temps on
     * success or failure and does not touch the deferred cross-block batch.
     */
    bool verify_block_batch();

    /**
     * Verify the finalized pending Spark batch when proofs are not being
     * collected. A no-op while collection is active, so IBD keeps
     * accumulating until a recent tip.
     *
     * @return true if collecting, if no batch is pending, or if the batch
     *         verifies; false on verification failure (pending proofs kept).
     */
    bool verify_pending();

    static bool HasRecoveryMarker();
    static void RemoveRecoveryMarker();

    bool add(const spark::SpendTransaction& tx, const uint256& txHash);
    bool addHistorical(const spark::SpendTransaction& tx, const uint256& txHash);
    void remove(const spark::SpendTransaction& tx);

private:
    static std::unique_ptr<BatchProofContainer> instance;
    mutable CCriticalSection cs_batch;
    bool fCollectProofs = false;
    bool fBatchFailed = false;
    std::vector<spark::SpendTransaction> tempSparkTransactions;
    std::vector<uint256> tempSparkTxIds;
    std::vector<spark::SpendTransaction> tempHistoricalSparkTransactions;
    std::vector<uint256> tempHistoricalSparkTxIds;
    std::vector<spark::SpendTransaction> sparkTransactions;
    std::vector<uint256> sparkTxIds;
    std::vector<spark::SpendTransaction> historicalSparkTransactions;
    std::vector<uint256> historicalSparkTxIds;
};

#endif //FIRO_BATCHPROOF_CONTAINER_H
