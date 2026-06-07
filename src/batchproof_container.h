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

    void verify();

    void add(const spark::SpendTransaction& tx);
    void remove(const spark::SpendTransaction& tx);
    void batch_spark();
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
