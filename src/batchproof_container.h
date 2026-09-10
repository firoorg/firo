#ifndef FIRO_BATCHPROOF_CONTAINER_H
#define FIRO_BATCHPROOF_CONTAINER_H

#include <memory>
#include "chain.h"
#include "libspark/spend_transaction.h"
#include "sync.h"

extern CChain chainActive;

class BatchProofContainer {
public:
    enum class Mode { Disabled, Deferred, Block };

    static BatchProofContainer* get_instance();

    void init(Mode mode = Mode::Disabled);

    void finalize();

    bool is_deferred() const;

    /** Verify this block's temps under cs_main, without touching pending proofs. */
    bool verify_block_batch();

    /**
     * Verify a retained snapshot, retrying if the pending batch or active tip
     * changes. Concurrent callers wait for the current verifier. Call without
     * cs_main: only snapshot preparation and verdict publication hold it.
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
    // Lock order: cs_verify -> cs_main. Collection never takes cs_verify.
    CCriticalSection cs_verify;
    // All remaining mutable state is protected by cs_main.
    Mode mode = Mode::Disabled;
    uint64_t generation = 0;
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
