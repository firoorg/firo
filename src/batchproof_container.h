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
     * Verify finalized Spark proofs unless proof collection is still active.
     *
     * @param nChainHeight Chain height for rebuilding cover sets; -1 uses the active tip.
     * @return true if collection is still active, no batch is pending, or the batch verifies; false on verification failure.
     */
    bool verify(int nChainHeight = -1);

    /**
     * Clear in-progress block proofs and verify already-finalized pending proofs.
     *
     * @param nChainHeight Chain height for rebuilding cover sets; -1 uses the active tip.
     * @return true if no finalized batch is pending or the batch verifies; false on verification failure.
     */
    bool verify_pending(int nChainHeight = -1);

    void add(const spark::SpendTransaction& tx);
    void remove(const spark::SpendTransaction& tx);

    /**
     * Run batch verification over finalized Spark spend transactions.
     *
     * @param nChainHeight Chain height for rebuilding cover sets; -1 uses the active tip.
     * @return true if the batch is empty or verifies; false on verification failure.
     */
    bool batch_spark(int nChainHeight = -1);
public:
    bool fCollectProofs = 0;

private:
    static std::unique_ptr<BatchProofContainer> instance;
    // temp spark transaction proofs
    std::vector<spark::SpendTransaction> tempSparkTransactions;

    // spark transaction proofs
    std::vector<spark::SpendTransaction> sparkTransactions;
};

#endif //FIRO_BATCHPROOF_CONTAINER_H
