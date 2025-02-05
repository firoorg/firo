#ifndef FIFO_SPARKNAME_H
#define FIFO_SPARKNAME_H

#include <chain.h>
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "evo/evodb.h"
#include "libspark/keys.h"

namespace spark {
    unsigned char GetNetworkType();
}

/*
 * Spark alias transaction data. This is to be stored in the transaction's extra data field
 * right after Spark data. The transaction is considered a Spark alias transaction if it spends
 * to a transparent output designated as an alias output, has this data in the extra data field
 * after Spark data, and has spent enough to cover the alias fee.
 */
class CSparkNameTxData
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    uint16_t nVersion{CURRENT_VERSION};     // version
    uint256 inputsHash;

    // 1-20 symbols, only alphanumeric characters and hyphens
    std::string name;
    // destination address for the alias
    std::string sparkAddress;
    // proof of ownership of the spark address
    std::vector<unsigned char> addressOwnershipProof;
    // number of blocks the spark name is valid for
    uint32_t sparkNameValidityBlocks{0};
    // additional information, string, up to 1024 symbols. Can be used for future extensions (e.g. for storing a web link)
    std::string additionalInfo;
    // failsafe if the hash of the transaction data is can't be converted to a scalar for proof creation/verification
    uint32_t hashFailsafe{0};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(inputsHash);
        READWRITE(name);
        READWRITE(sparkAddress);
        READWRITE(addressOwnershipProof);
        READWRITE(sparkNameValidityBlocks);
        READWRITE(additionalInfo);
        READWRITE(hashFailsafe);
    }
};

class CSparkNameManager
{
private:
    static CSparkNameManager *sharedSparkNameManager;

    std::map<std::string, std::pair<spark::Address, uint32_t>> sparkNames;
    std::map<spark::Address, std::string> sparkNameAddresses;

public:
    CSparkNameManager() {}

    // Parse spark name transaction data from the transaction. Sets fCriticalError to false if there is no name data found
    // but the transaction is otherwise valid. Returns true if the transaction is a valid spark name transaction.
    static bool ParseSparkNameTxData(const CTransaction &tx, spark::SpendTransaction &sparkTx, CSparkNameTxData &sparkNameData, size_t &sparkNameDataPos);

    bool CheckSparkNameTx(const CTransaction &tx, int nHeight, CValidationState &state, CSparkNameTxData *outSparkNameData = nullptr);

    // test if the spark name tx is valid
    bool IsSparkNameValid(const CTransaction &tx, CValidationState &state);

    // return all valid names
    std::set<std::string> GetSparkNames(int nHeight);

    // return the address associated with the spark name
    bool GetSparkAddress(const std::string &name, int nHeight, spark::Address &address);

    // resolution of conflicts (e.g. for mempool)
    // TxSet is a set of transactions that might be in conflict with the txData. Should implement contains() method
    template <class TxSet>
    static bool IsInConflict(CSparkNameTxData &txData, const TxSet &txSet)
    {
        std::string upperName = ToUpper(txData.name);
        return txSet.find(upperName) != txSet.cend();
    }

    template <class TxSet>
    static bool IsInConflict(CSparkNameTxData &txData, const TxSet &txSet, std::function<std::string(typename TxSet::const_iterator)> getAddress)
    {
        std::string upperName = ToUpper(txData.name);
        if (txSet.find(upperName) != txSet.cend())
            return true;

        for (typename TxSet::const_iterator it = txSet.cbegin(); it != txSet.cend(); ++it)
        {
            if (getAddress(it) == txData.sparkAddress)
                return true;
        }

        return false;
    }

    // fill missing CSparkNameTxData fields and append spark name tx data to the transaction
    void AppendSparkNameTxData(CMutableTransaction &txSparkSpend, CSparkNameTxData &sparkNameData, const spark::SpendKey &spendKey, const spark::IncomingViewKey &incomingViewKey);

    // add and remove spark name
    bool AddSparkName(const std::string &name, const spark::Address &address, uint32_t validityBlocks);
    bool RemoveSparkName(const std::string &name, const spark::Address &address);

    static CSparkNameManager *GetInstance() { return sharedSparkNameManager; };

    uint64_t GetSparkNameBlockHeight(const std::string &name) const;

    std::string GetSparkNameTxID(const std::string &name) const;

    std::map<std::string, std::pair<std::string, uint32_t>> RemoveSparkNamesLosingValidity(int nHeight);

    bool AddBlock(CBlockIndex *pindex);
    bool RemoveBlock(CBlockIndex *pindex);

    static std::string ToUpper(const std::string &sparkName);
};

#endif // FIRO_SPARKNAME_H