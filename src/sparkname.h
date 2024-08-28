#ifndef FIFO_SPARKNAME_H
#define FIFO_SPARKNAME_H

#include <chain.h>
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "evo/evodb.h"
#include "libspark/keys.h"

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
    spark::Address sparkAddress;
    // proof of ownership of the spark address
    std::vector<unsigned char> addressOwnershipProof;
    // number of blocks the spark name is valid for
    uint32_t sparkNameValidityBlocks{0};

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
    }
};

class CSparkNameManager
{
private:
    static CSparkNameManager *sharedAliasManager;

    std::map<std::string, std::pair<spark::Address, uint32_t>> sparkNames;

public:
    CSparkNameManager() {}

    // update the state with contents of spark name transactions containted in block
    bool BlockConnected(CBlockIndex *pindex);
    bool BlockDisconnected(CBlockIndex *pindex);

    bool CheckSparkNameTx(const CTransaction &tx, int nHeight, CValidationState &state);

    // test if the spark name tx is valid
    bool IsSparkNameValid(const CTransaction &tx, CValidationState &state);

    // return all valid names
    std::set<std::string> GetSparkNames(int nHeight);

    // return the address associated with the spark name
    bool GetSparkAddress(const std::string &name, int nHeight, spark::Address &address);

    static CSparkNameManager *GetAliasManager() { return sharedAliasManager; };
};

#endif // FIRO_SPARKNAME_H