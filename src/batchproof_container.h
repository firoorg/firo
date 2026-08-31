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

    void init(bool collectProofs = false);

    void abort();

    void finalize();

    /**
     * Verify the finalized Spark batch for the current block. A no-op while
     * collection is active.
     *
     * @return true if collecting, if no batch is pending, or if the batch
     *         verifies; false on verification failure.
     */
    bool verify_pending();

    static bool HasRecoveryMarker();
    static void RemoveRecoveryMarker();

    bool add(const spark::SpendTransaction& tx, const uint256& txHash);
    bool addHistorical(const spark::SpendTransaction& tx, const uint256& txHash);

private:
    static std::unique_ptr<BatchProofContainer> instance;
    mutable CCriticalSection cs_batch;
    bool fCollectProofs = false;
    std::vector<spark::SpendTransaction> sparkTransactions;
    std::vector<uint256> sparkTxIds;
    std::vector<spark::SpendTransaction> historicalSparkTransactions;
    std::vector<uint256> historicalSparkTxIds;
};

#endif //FIRO_BATCHPROOF_CONTAINER_H
