#ifndef FIRO_BATCHPROOF_CONTAINER_H
#define FIRO_BATCHPROOF_CONTAINER_H

#include <memory>
#include "chain.h"
#include "liblelantus/joinsplit.h"
#include "libspark/spend_transaction.h"

extern CChain chainActive;

class BatchProofContainer {
public:
    static BatchProofContainer* get_instance();

    struct LelantusSigmaProofData {
        LelantusSigmaProofData(const lelantus::SigmaExtendedProof& lelantusSigmaProof_,
                               const Scalar& serialNumber_,
                               const Scalar& challenge_,
                               size_t anonymitySetSize_)
                               : lelantusSigmaProof(lelantusSigmaProof_),
                               serialNumber(serialNumber_),
                               challenge(challenge_),
                               anonymitySetSize(anonymitySetSize_) {}

        lelantus::SigmaExtendedProof lelantusSigmaProof;
        Scalar serialNumber;
        Scalar challenge;
        size_t anonymitySetSize;
    };

    void init();

    void finalize();

    void verify();

    void add(lelantus::JoinSplit* joinSplit,
             const std::map<uint32_t, size_t>& setSizes,
             const Scalar& challenge,
             bool fStartLelantusBlacklist);

    void add(lelantus::JoinSplit* joinSplit, const std::vector<lelantus::PublicCoin>& Cout);

    void removeLelantus(std::unordered_map<Scalar, int> spentSerials);
    void remove(const std::vector<lelantus::RangeProof>& rangeProofsToRemove);
    void erase(std::vector<LelantusSigmaProofData>* vProofs, const Scalar& serial);

    void batch_lelantus();
    void batch_rangeProofs();

    void add(const spark::SpendTransaction& tx);
    void remove(const spark::SpendTransaction& tx);
    void batch_spark();
public:
    bool fCollectProofs = 0;

private:
    static std::unique_ptr<BatchProofContainer> instance;
    // temp containers, to forget in case block connection fails
    // map ((id, afterFixes), fIsSigmaToLelantus) to (sigma proof, serial, set size, challenge)
    std::map<std::pair<uint32_t, bool>, std::vector<LelantusSigmaProofData>> tempLelantusSigmaProofs;
    // map (version to (Range proof, Pubcoins))
    std::map<unsigned int, std::vector<std::pair<lelantus::RangeProof, std::vector<lelantus::PublicCoin>>>> tempRangeProofs;
    // temp spark transaction proofs
    std::vector<spark::SpendTransaction> tempSparkTransactions;

    // containers to keep proofs for batching
    std::map<std::pair<uint32_t, bool>, std::vector<LelantusSigmaProofData>> lelantusSigmaProofs;
    std::map<unsigned int, std::vector<std::pair<lelantus::RangeProof, std::vector<lelantus::PublicCoin>>>> rangeProofs;
    // spark transaction proofs
    std::vector<spark::SpendTransaction> sparkTransactions;
};

#endif //FIRO_BATCHPROOF_CONTAINER_H
