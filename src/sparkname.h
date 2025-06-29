#ifndef FIFO_SPARKNAME_H
#define FIFO_SPARKNAME_H

#include <chain.h>
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "evo/evodb.h"
#include "libspark/keys.h"
#include "libspark/spend_transaction.h"

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

/*
 * Spark name record as it appears in the block index data. This is used to keep track of the added/removed
 * spark names in a block.
 */

struct CSparkNameBlockIndexData {
    // 1-20 symbols, only alphanumeric characters and hyphens
    std::string name;
    // destination address for the alias
    std::string sparkAddress;
    // spark name is valid until this block height
    uint32_t sparkNameValidityHeight{0};
    // additional information
    std::string additionalInfo;

    CSparkNameBlockIndexData() {}
    CSparkNameBlockIndexData(const std::string _name, const std::string _sparkAddress, uint32_t _sparkNameValidityHeight, const std::string _additionalInfo)
        : name(_name), sparkAddress(_sparkAddress), sparkNameValidityHeight(_sparkNameValidityHeight), additionalInfo(_additionalInfo) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(sparkAddress);
        READWRITE(sparkNameValidityHeight);
        READWRITE(additionalInfo);
    }
};

class CSparkNameManager
{
private:
    static CSparkNameManager *sharedSparkNameManager;

    std::map<std::string, CSparkNameBlockIndexData> sparkNames;
    std::map<std::string, std::string> sparkNameAddresses;

public:
    static const unsigned maximumSparkNameLength = 20;

    CSparkNameManager() {}

    // Parse spark name transaction data from the transaction. Sets fCriticalError to false if there is no name data found
    // but the transaction is otherwise valid. Returns true if the transaction is a valid spark name transaction.
    static bool ParseSparkNameTxData(const CTransaction &tx, spark::SpendTransaction &sparkTx, CSparkNameTxData &sparkNameData, size_t &sparkNameDataPos);

    bool CheckSparkNameTx(const CTransaction &tx, int nHeight, CValidationState &state, CSparkNameTxData *outSparkNameData = nullptr);

    // test if the spark name is valid
    static bool IsSparkNameValid(const std::string &name);

    // return all valid names
    std::set<std::string> GetSparkNames();

    // dump all the spark names along with data
    std::vector<CSparkNameBlockIndexData> DumpSparkNameData();

    // return the address associated with the spark name
    bool GetSparkAddress(const std::string &name, std::string &address);

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

    // check the possibility to register a new spark name, return true if it's possible
    bool ValidateSparkNameData(const CSparkNameTxData &sparkNameData, std::string &errorDescription);

    // Checking if an address is occupied with spark name
    bool GetSparkNameByAddress(const std::string& address, std::string& name);

    // get the size of the spark name transaction metadata
    size_t GetSparkNameTxDataSize(const CSparkNameTxData &sparkNameData);

    // fill missing CSparkNameTxData fields and append spark name tx data to the transaction
    void AppendSparkNameTxData(CMutableTransaction &txSparkSpend, CSparkNameTxData &sparkNameData, const spark::SpendKey &spendKey, const spark::IncomingViewKey &incomingViewKey);

    // add and remove spark name
    bool AddSparkName(const std::string &name, const std::string &address, uint32_t validityBlocks, const std::string &additionalInfo);
    bool RemoveSparkName(const std::string &name, const std::string &address);

    static CSparkNameManager *GetInstance() { return sharedSparkNameManager; };

    uint64_t GetSparkNameBlockHeight(const std::string &name) const;

    std::string GetSparkNameAdditionalData(const std::string &name) const;

    std::map<std::string, CSparkNameBlockIndexData> RemoveSparkNamesLosingValidity(int nHeight);

    bool AddBlock(CBlockIndex *pindex, bool fBackupRewrittenEntries = false);
    bool RemoveBlock(CBlockIndex *pindex);

    static std::string ToUpper(const std::string &sparkName);

    // reset method for test purposes only
    void Reset();
};

#endif // FIRO_SPARKNAME_H