#include "chain.h"
#include "libspark/spend_transaction.h"
#include "libspark/ownership_proof.h"
#include "libspark/keys.h"
#include "spark/state.h"
#include "script/standard.h"
#include "base58.h"
#include "sparkname.h"

CSparkNameManager *CSparkNameManager::sharedAliasManager = new CSparkNameManager();

bool CSparkNameManager::BlockConnected(CBlockIndex *pindex)
{
    for (const auto &entry : pindex->addedSparkNames)
        sparkNames[entry.first] = entry.second;

    for (const auto &entry : pindex->removedSparkNames)
        sparkNames.erase(entry.first);

    return true;
}

bool CSparkNameManager::BlockDisconnected(CBlockIndex *pindex)
{
    for (const auto &entry : pindex->addedSparkNames)
        sparkNames.erase(entry.first);

    for (const auto &entry : pindex->removedSparkNames)
        sparkNames[entry.first] = entry.second;

    return true;
}

std::set<std::string> CSparkNameManager::GetSparkNames(int nHeight)
{
    std::set<std::string> result;
    for (const auto &entry : sparkNames)
        if (entry.second.second >= nHeight)
            result.insert(entry.first);

    return result;
}

bool CSparkNameManager::GetSparkAddress(const std::string &name, int nHeight, spark::Address &address)
{
    auto it = sparkNames.find(name);
    if (it == sparkNames.end() || it->second.second < nHeight) {
        address = it->second.first;
        return true;
    }
    else {
        return false;
    }
}

bool CSparkNameManager::ParseSparkNameTxData(const CTransaction &tx, spark::SpendTransaction &sparkTx, CSparkNameTxData &sparkNameData, size_t &sparkNameDataPos)
{
    CDataStream serializedSpark(SER_NETWORK, PROTOCOL_VERSION);
    serializedSpark.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    try {
        serializedSpark >> sparkTx;
        if (serializedSpark.size() == 0) {
            // silently ignore, it's not a critical error to not have a spark name tx part
            return false;
        }

        sparkNameDataPos = tx.vExtraPayload.size() - serializedSpark.size();
        serializedSpark >> sparkNameData;
    }
    catch (const std::exception &) {
        return false;
    }

    return true;
}

bool CSparkNameManager::CheckSparkNameTx(const CTransaction &tx, int nHeight, CValidationState &state)
{
    const Consensus::Params &consensusParams = Params().GetConsensus();

    if (!tx.IsSparkSpend())
        return state.Error("CheckSparkNameTx: not a spark name tx");

    CSparkNameTxData sparkNameData;
    const spark::Params *params = spark::Params::get_default();
    spark::SpendTransaction spendTransaction(params);
    size_t sparkNameDataPos;

    if (!ParseSparkNameTxData(tx, spendTransaction, sparkNameData, sparkNameDataPos))
        return state.DoS(100, error("CheckSparkNameTx: failed to parse spark name tx"));

    if (nHeight < consensusParams.nSparkNamesStartBlock)
        return state.DoS(100, error("CheckSparkNameTx: spark names are not allowed before block %d", consensusParams.nSparkStartBlock));

    if (sparkNameData.name.size() < 1 || sparkNameData.name.size() > 20)
        return state.DoS(100, error("CheckSparkNameTx: invalid name length"));

    for (char c: sparkNameData.name)
        if (!isalnum(c) && c != '-')
            return state.DoS(100, error("CheckSparkNameTx: invalid name"));

    constexpr int nBlockPerYear = 365*24*24; // 24 blocks per hour
    int nYears = (sparkNameData.sparkNameValidityBlocks + nBlockPerYear-1) / nBlockPerYear;

    if (sparkNameData.sparkNameValidityBlocks > nBlockPerYear * 5)
        return state.DoS(100, error("CheckSparkNameTx: can't be valid for more than 5 years"));

    CAmount nameFee = consensusParams.nSparkNamesFee[sparkNameData.name.size()] * nYears;
    CScript devPayoutScript = GetScriptForDestination(CBitcoinAddress(consensusParams.stage3DevelopmentFundAddress).Get());
    bool payoutFound = false;
    for (const CTxOut &txout: tx.vout)
        if (txout.scriptPubKey == devPayoutScript && txout.nValue >= nameFee) {
            payoutFound = true;
            break;
        }

    if (!payoutFound)
        return state.DoS(100, error("CheckSparkNameTx: name fee is either missing or insufficient"));

    if (sparkNameData.additionalInfo.size() > 1024)
        return state.DoS(100, error("CheckSparkNameTx: additional info is too long"));

    unsigned char sparkNetworkType = spark::GetNetworkType();
    if (sparkNames.count(sparkNameData.name) > 0 &&
                sparkNames[sparkNameData.name].first.encode(sparkNetworkType) != sparkNameData.sparkAddress)
        return state.DoS(100, error("CheckSparkNameTx: name already exists"));

    // calculate the hash of the all the transaction except the spark ownership proof
    CMutableTransaction txMutable(tx);
    CSparkNameTxData sparkNameDataCopy = sparkNameData;
    
    txMutable.vExtraPayload.erase(txMutable.vExtraPayload.begin() + sparkNameDataPos, txMutable.vExtraPayload.end());
    sparkNameDataCopy.addressOwnershipProof.clear();
    CDataStream serializedSparkNameData(SER_NETWORK, PROTOCOL_VERSION);
    serializedSparkNameData << sparkNameDataCopy;
    txMutable.vExtraPayload.insert(txMutable.vExtraPayload.end(), serializedSparkNameData.begin(), serializedSparkNameData.end());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << txMutable;
    spark::OwnershipProof ownershipProof;

    try {
        CDataStream ownershipProofStream(SER_NETWORK, PROTOCOL_VERSION);
        ownershipProofStream.write((const char *)sparkNameData.addressOwnershipProof.data(), sparkNameData.addressOwnershipProof.size());
        ownershipProofStream >> ownershipProof;
    }
    catch (const std::exception &) {
        return state.DoS(100, error("CheckSparkNameTx: failed to deserialize ownership proof"));
    }

    spark::Scalar m;
    try {
        m.SetHex(ss.GetHash().ToString());
    }
    catch (const std::exception &) {
        return state.DoS(100, error("CheckSparkNameTx: hash is out of range"));
    }

    spark::Address sparkAddress;
    try {
        sparkAddress.decode(sparkNameData.sparkAddress);
    }
    catch (const std::exception &) {
        return state.DoS(100, error("CheckSparkNameTx: cannot decode spark address"));
    }

    if (!sparkAddress.verify_own(m, ownershipProof))
        return state.DoS(100, error("CheckSparkNameTx: ownership proof is invalid"));

    return true;
}