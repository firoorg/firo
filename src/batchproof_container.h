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

    /** Discard this block's temps and select a mode; retain pending proofs and their failure state. */
    void init(Mode mode = Mode::Disabled);

    /**
     * Append deferred block proofs, then disable collection. Does not verify proofs.
     * Block mode must be verified with verify_block_batch() first.
     */
    void finalize();

    bool is_deferred() const;

    /** Verify this block's temps under cs_main, without touching pending proofs. */
    bool verify_block_batch();

    /**
     * Verify a retained snapshot, retrying if the pending batch or active tip
     * changes. Concurrent callers wait for the current verifier. Call without
     * cs_main: only snapshot preparation and verdict publication hold it.
     *
     * While collecting, returns true without checking pending proofs.
     * @return true if no batch is pending or it verifies; false on verification
     *         failure (pending proofs kept).
     */
    bool verify_pending();

    static bool HasRecoveryMarker();
    static void RemoveRecoveryMarker();

    bool add(const spark::SpendTransaction& tx, const uint256& txHash);
    /** Use legacy proof rules; separate from Deferred mode's accumulation of old blocks. */
    bool addHistorical(const spark::SpendTransaction& tx, const uint256& txHash);
    void remove(const spark::SpendTransaction& tx);

private:
    // Lock order: cs_verify -> cs_main. Collection never takes cs_verify.
    CCriticalSection cs_verify;
    // All remaining mutable state is protected by cs_main.
    Mode mode = Mode::Disabled;
    uint64_t generation = 0;
    // Fail fast until proofs are removed from the failed pending batch.
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
