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
     * Discard any in-progress per-block collection and verify the finalized
     * pending Spark batch.
     *
     * @return true if no batch is pending or the batch verifies; false on
     *         verification failure, in which case the pending proofs are kept.
     */
    bool verify_pending();

    void add(const spark::SpendTransaction& tx, const uint256& txHash);
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

    // spark transaction proofs and the txids they came from
    std::vector<spark::SpendTransaction> sparkTransactions;
    std::vector<uint256> sparkTxIds;
};

#endif //FIRO_BATCHPROOF_CONTAINER_H
