#include "chain.h"
#include "libspark/spend_transaction.h"
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

bool CSparkNameManager::CheckSparkNameTx(const CTransaction &tx, int nHeight, CValidationState &state)
{
    const Consensus::Params &consensusParams = Params().GetConsensus();

    if (!tx.IsSparkSpend())
        return state.Error("CheckSparkNameTx: not a spark name tx");

    CSparkNameTxData sparkNameData;
    
    CDataStream serializedSpark(SER_NETWORK, PROTOCOL_VERSION);
    serializedSpark.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    const spark::Params *params = spark::Params::get_default();
    spark::SpendTransaction spendTransaction(params);
    try {
        serializedSpark >> spendTransaction;
        if (serializedSpark.size() == 0)
            // silently ignore
            return true;

        serializedSpark >> sparkNameData;
    }
    catch (const std::exception &) {
        return state.DoS(100, error("CheckSparkNameTx: failed to deserialize spend"));
    }

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

    if (sparkNames.count(sparkNameData.name) > 0 && sparkNames[sparkNameData.name].first.encode() != sparkNameData.sparkAddress.encode())
        return state.DoS(100, error("CheckSparkNameTx: name already exists"));

    return true;
}