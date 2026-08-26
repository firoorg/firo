#ifndef FIRO_BATCHPROOF_CONTAINER_H
#define FIRO_BATCHPROOF_CONTAINER_H

#include <memory>
#include "chain.h"
#include "libspark/spend_transaction.h"

extern CChain chainActive;

class BatchProofContainer {
public:
    static BatchProofContainer* get_instance();

    void init();

    void finalize();

    /**
     * Verify the finalized pending Spark batch when proofs are not being
     * collected. Matches master's verify() gate: a no-op while fCollectProofs
     * is set, so IBD keeps accumulating until a recent tip.
     *
     * @return true if collecting, if no batch is pending, or if the batch
     *         verifies; false on verification failure (pending proofs kept).
     */
    bool verify_pending();

    void add(const spark::SpendTransaction& tx, const uint256& txHash);
    void addHistorical(const spark::SpendTransaction& tx, const uint256& txHash);
    void remove(const spark::SpendTransaction& tx);
public:
    bool fCollectProofs = 0;

private:
    bool batch_spark();

    static std::unique_ptr<BatchProofContainer> instance;
    // a pending batch failed verification; fail fast until the batch changes
    bool fBatchFailed = false;
    // temp spark transaction proofs and the txids they came from
    std::vector<spark::SpendTransaction> tempSparkTransactions;
    std::vector<uint256> tempSparkTxIds;
    std::vector<spark::SpendTransaction> tempHistoricalSparkTransactions;
    std::vector<uint256> tempHistoricalSparkTxIds;

    // spark transaction proofs and the txids they came from
    std::vector<spark::SpendTransaction> sparkTransactions;
    std::vector<uint256> sparkTxIds;
    std::vector<spark::SpendTransaction> historicalSparkTransactions;
    std::vector<uint256> historicalSparkTxIds;
};

#endif //FIRO_BATCHPROOF_CONTAINER_H
