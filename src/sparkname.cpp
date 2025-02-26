#include "chain.h"
#include "libspark/spend_transaction.h"
#include "libspark/ownership_proof.h"
#include "libspark/keys.h"
#include "spark/state.h"
#include "script/standard.h"
#include "base58.h"
#include "sparkname.h"
#include "validation.h"
#include "ui_interface.h"

CSparkNameManager *CSparkNameManager::sharedSparkNameManager = new CSparkNameManager();

bool CSparkNameManager::AddBlock(CBlockIndex *pindex, bool fBackupRewrittenEntries)
{
    for (const auto &entry : pindex->removedSparkNames) {
        sparkNameAddresses.erase(entry.second.sparkAddress);
        sparkNames.erase(ToUpper(entry.first));
        uiInterface.NotifySparkNameRemoved(entry.second);
    }

    for (const auto &entry : pindex->addedSparkNames) {
        std::string upperName = ToUpper(entry.first);
        if (sparkNames.count(upperName) > 0 && fBackupRewrittenEntries)
            pindex->removedSparkNames[upperName] = sparkNames[upperName];
        sparkNames[upperName] = entry.second;
        sparkNameAddresses[entry.second.sparkAddress] = upperName;
        uiInterface.NotifySparkNameAdded(entry.second);
    }

    return true;
}

bool CSparkNameManager::RemoveBlock(CBlockIndex *pindex)
{
    for (const auto &entry : pindex->addedSparkNames) {
        sparkNames.erase(ToUpper(entry.first));
        sparkNameAddresses.erase(entry.second.sparkAddress);
        uiInterface.NotifySparkNameRemoved(entry.second);
    }

    for (const auto &entry : pindex->removedSparkNames) {
        sparkNames[ToUpper(entry.first)] = entry.second;
        sparkNameAddresses[entry.second.sparkAddress] = ToUpper(entry.first);
        uiInterface.NotifySparkNameAdded(entry.second);
    }

    return true;
}

std::set<std::string> CSparkNameManager::GetSparkNames()
{
    std::set<std::string> result;
    for (const auto &entry : sparkNames)
        result.insert(entry.second.name);

    return result;
}

std::vector<CSparkNameBlockIndexData> CSparkNameManager::DumpSparkNameData()
{
    std::vector<CSparkNameBlockIndexData> result;
    result.reserve(sparkNames.size());
    for (const auto &entry : sparkNames)
        result.push_back(entry.second);

    return result;
}

bool CSparkNameManager::GetSparkAddress(const std::string &name, std::string &address)
{
    auto it = sparkNames.find(ToUpper(name));
    if (it != sparkNames.end()) {
        address = it->second.sparkAddress;
        return true;
    }
    else {
        return false;
    }
}

uint64_t CSparkNameManager::GetSparkNameBlockHeight(const std::string &name) const
{
    auto it = sparkNames.find(ToUpper(name));
    if (it == sparkNames.end())
       throw std::runtime_error("Spark name not found: " + name);

    size_t height = it->second.sparkNameValidityHeight;
    return height;
}

std::string CSparkNameManager::GetSparkNameAdditionalData(const std::string &name) const
{
    auto it = sparkNames.find(ToUpper(name));
    if (it == sparkNames.end())
        throw std::runtime_error("Spark name not found: " + name);

    return it->second.additionalInfo;
}

bool CSparkNameManager::ParseSparkNameTxData(const CTransaction &tx, spark::SpendTransaction &sparkTx, CSparkNameTxData &sparkNameData, size_t &sparkNameDataPos)
{
    sparkNameDataPos = 0;
    CDataStream serializedSpark(SER_NETWORK, PROTOCOL_VERSION);
    serializedSpark.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    try {
        serializedSpark >> sparkTx;
        if (serializedSpark.size() == 0) {
            // silently ignore, it's not a critical error to not have a spark name tx part
            // sparkNameDataPos pointing to the end of the tx payload means there is no spark name tx data
            sparkNameDataPos = tx.vExtraPayload.size();
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

bool CSparkNameManager::CheckSparkNameTx(const CTransaction &tx, int nHeight, CValidationState &state, CSparkNameTxData *outSparkNameData)
{
    const Consensus::Params &consensusParams = Params().GetConsensus();

    if (outSparkNameData)
        outSparkNameData->name.clear();

    if (!tx.IsSparkSpend())
        return state.Error("CheckSparkNameTx: not a spark name tx");

    CSparkNameTxData sparkNameData;
    const spark::Params *params = spark::Params::get_default();
    spark::SpendTransaction spendTransaction(params);
    size_t sparkNameDataPos;

    if (!ParseSparkNameTxData(tx, spendTransaction, sparkNameData, sparkNameDataPos)) {
        if (sparkNameDataPos == tx.vExtraPayload.size()) {
            return true;    // no payload, not an error at all
        }
        else {
            return state.DoS(100, error("CheckSparkNameTx: failed to parse spark name tx"));
        }
    }

    if (outSparkNameData)
        *outSparkNameData = sparkNameData;

    if (nHeight < consensusParams.nSparkNamesStartBlock)
        return state.DoS(100, error("CheckSparkNameTx: spark names are not allowed before block %d", consensusParams.nSparkStartBlock));

    if (!IsSparkNameValid(sparkNameData.name))
        return state.DoS(100, error("CheckSparkNameTx: invalid name"));

    constexpr int nBlockPerYear = 365*24*24; // 24 blocks per hour
    int nYears = (sparkNameData.sparkNameValidityBlocks + nBlockPerYear-1) / nBlockPerYear;

    if (sparkNameData.sparkNameValidityBlocks > nBlockPerYear * 10)
        return state.DoS(100, error("CheckSparkNameTx: can't be valid for more than 10 years"));

    CAmount nameFee = consensusParams.nSparkNamesFee[sparkNameData.name.size()] * COIN * nYears;
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
    if (sparkNames.count(ToUpper(sparkNameData.name)) > 0 &&
                sparkNames[ToUpper(sparkNameData.name)].sparkAddress != sparkNameData.sparkAddress)
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

    spark::Address sparkAddress(spark::Params::get_default());
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

bool CSparkNameManager::ValidateSparkNameData(const CSparkNameTxData &sparkNameData, std::string &errorDescription)
{
    errorDescription.clear();

    if (!IsSparkNameValid(sparkNameData.name))
        errorDescription = "invalid spark name";

    else if (sparkNameData.additionalInfo.size() > 1024)
        errorDescription = "additional info is too long";

    else if (sparkNameData.sparkNameValidityBlocks > 365*24*24*10)
        errorDescription = "transaction can't be valid for more than 10 years";

    else if (sparkNames.count(ToUpper(sparkNameData.name)) > 0 &&
                sparkNames[ToUpper(sparkNameData.name)].sparkAddress != sparkNameData.sparkAddress)
        errorDescription = "name already exists with another spark address as a destination";

    else if (sparkNameAddresses.count(sparkNameData.sparkAddress) > 0 &&
                sparkNameAddresses[sparkNameData.sparkAddress] != ToUpper(sparkNameData.name))
        errorDescription = "spark address is already used for another name";

    else {
        LOCK(mempool.cs);
        if (mempool.sparkNames.count(ToUpper(sparkNameData.name)) > 0)
            errorDescription = "spark name transaction with that name is already in the mempool";
    }

    return errorDescription.empty();
}

void CSparkNameManager::AppendSparkNameTxData(CMutableTransaction &txSparkSpend, CSparkNameTxData &sparkNameData, const spark::SpendKey &spendKey, const spark::IncomingViewKey &incomingViewKey, size_t &additionalSize)
{
    for (uint32_t n=0; ; n++) {
        sparkNameData.addressOwnershipProof.clear();
        sparkNameData.hashFailsafe = n;

        CMutableTransaction txCopy(txSparkSpend);
        CDataStream serializedSparkNameData(SER_NETWORK, PROTOCOL_VERSION);
        serializedSparkNameData << sparkNameData;
        txCopy.vExtraPayload.insert(txCopy.vExtraPayload.end(), serializedSparkNameData.begin(), serializedSparkNameData.end());

        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << txCopy;

        spark::Scalar m;
        try {
            m.SetHex(ss.GetHash().ToString());
        }
        catch (const std::exception &) {
            continue;   // increase hashFailSafe and try again
        }

        spark::Address sparkAddress(spark::Params::get_default());
        spark::OwnershipProof ownershipProof;

        sparkAddress.decode(sparkNameData.sparkAddress);
        sparkAddress.prove_own(m, spendKey, incomingViewKey, ownershipProof);

        CDataStream ownershipProofStream(SER_NETWORK, PROTOCOL_VERSION);
        ownershipProofStream << ownershipProof;

        sparkNameData.addressOwnershipProof.assign(ownershipProofStream.begin(), ownershipProofStream.end());

        CDataStream sparkNameDataStream(SER_NETWORK, PROTOCOL_VERSION);
        sparkNameDataStream << sparkNameData;

        additionalSize = sparkNameDataStream.size();
        txSparkSpend.vExtraPayload.insert(txSparkSpend.vExtraPayload.end(), sparkNameDataStream.begin(), sparkNameDataStream.end());

        break;
    }
}

std::string CSparkNameManager::ToUpper(const std::string &str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

bool CSparkNameManager::AddSparkName(const std::string &name, const std::string &address, uint32_t validityBlocks, const std::string &additionalInfo)
{
    std::string upperName = ToUpper(name);

    if (sparkNames.count(upperName) > 0 && address != sparkNames[upperName].sparkAddress)
        return false;
    else if (sparkNameAddresses.count(address) > 0)
        return false;

    sparkNames[upperName] = CSparkNameBlockIndexData(name, address, validityBlocks, additionalInfo);
    sparkNameAddresses[address] = upperName;
    uiInterface.NotifySparkNameAdded(sparkNames[upperName]);

    return true;
}

bool CSparkNameManager::RemoveSparkName(const std::string &name, const std::string &address)
{
    std::string upperName = ToUpper(name);

    if (sparkNames.count(upperName) == 0 || sparkNameAddresses.count(address) == 0)
        return false;

    CSparkNameBlockIndexData sparkNameData = sparkNames[upperName];
    sparkNames.erase(upperName);
    sparkNameAddresses.erase(address);
    uiInterface.NotifySparkNameRemoved(sparkNameData);
    
    return true;
}

std::map<std::string, CSparkNameBlockIndexData> CSparkNameManager::RemoveSparkNamesLosingValidity(int nHeight)
{
    std::map<std::string, CSparkNameBlockIndexData> result;

    for (auto it = sparkNames.begin(); it != sparkNames.end();)
        if (nHeight >= it->second.sparkNameValidityHeight) {
            std::string sparkAddressStr = it->second.sparkAddress;
            sparkNameAddresses.erase(sparkAddressStr);
            result[it->first] = it->second;
            it = sparkNames.erase(it);
        }
        else
            ++it;

    return result;
}

bool CSparkNameManager::IsSparkNameValid(const std::string &name)
{
    if (name.size() < 1 || name.size() > maximumSparkNameLength)
        return false;

    for (char c: name)
        if (!isalnum(c) && c != '-' && c != '.')
            return false;

    return true;
}