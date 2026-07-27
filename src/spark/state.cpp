#include "threadpool.h"
#include "state.h"
#include "compat_layer.h"
#include "sparkname.h"
#include "../validation.h"
#include "../batchproof_container.h"
#include "../saltedhasher.h"
#include "../sync.h"
#include "../unordered_lru_cache.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <set>
#include <unordered_set>

namespace spark {

// Bound the mempool-acceptance proof cache to successful verifications. Failed
// proofs are not stored, so a later relay of the same payload is verified again.
// DisconnectTipSpark clears the cache on reorg; entries are also removed when
// the mempool drops the transaction.
static constexpr size_t MAX_CHECKED_SPARK_SPEND_TRANSACTIONS = 10000;
static CCriticalSection cs_checkedSparkSpendTransactions;
static unordered_lru_cache<uint256, bool, StaticSaltedHasher, MAX_CHECKED_SPARK_SPEND_TRANSACTIONS>
    gCheckedSparkSpendTransactions(MAX_CHECKED_SPARK_SPEND_TRANSACTIONS);

void EraseCheckedSparkSpendTransaction(const uint256& hashTx)
{
    LOCK(cs_checkedSparkSpendTransactions);
    gCheckedSparkSpendTransactions.erase(hashTx);
}

void ClearSparkSpendProofCache()
{
    LOCK(cs_checkedSparkSpendTransactions);
    gCheckedSparkSpendTransactions.clear();
}

std::size_t GetSparkSpendProofCacheSize()
{
    LOCK(cs_checkedSparkSpendTransactions);
    return gCheckedSparkSpendTransactions.size();
}

static CSparkState sparkState;
static thread_local CSparkVerifyDBContext* activeVerifyDBContext = nullptr;

static CSparkState& SparkStateForValidation(bool isVerifyDB)
{
    if (isVerifyDB && activeVerifyDBContext) {
        return activeVerifyDBContext->GetSparkState();
    }
    return sparkState;
}

static CSparkNameManager* SparkNameManagerForValidation(bool isVerifyDB)
{
    if (isVerifyDB && activeVerifyDBContext) {
        return &activeVerifyDBContext->GetSparkNameManager();
    }
    return CSparkNameManager::GetInstance();
}

CSparkVerifyDBContext::CSparkVerifyDBContext(CBlockIndex* tip) :
    previous(activeVerifyDBContext)
{
    state.CopyFrom(sparkState);
    sparkNameManager.CopyFrom(*CSparkNameManager::GetInstance());
    for (CBlockIndex* index = chainActive.Tip();
         index && index != tip;
         index = index->pprev) {
        state.RemoveBlock(index);
        sparkNameManager.RemoveBlock(index, false);
    }
    activeVerifyDBContext = this;
}

CSparkVerifyDBContext::~CSparkVerifyDBContext()
{
    activeVerifyDBContext = previous;
}

void CSparkVerifyDBContext::AddBlock(CBlockIndex* index)
{
    state.AddBlock(index);
    sparkNameManager.AddBlock(index, false, false);
}

CSparkVerifyDBContext* CSparkVerifyDBContext::GetActive()
{
    return activeVerifyDBContext;
}

bool CheckSparkMintDuplicates(
        CValidationState& state,
        const std::vector<spark::Coin>& mints,
        int nHeight)
{
    std::unordered_set<uint256> blockMints;
    for (const auto& mint : mints) {
        const auto mintedCoinHeightAndId =
            sparkState.GetMintedCoinHeightAndId(mint);
        if (!blockMints.insert(mint.getHash()).second ||
                (mintedCoinHeightAndId.first >= 0 &&
                 mintedCoinHeightAndId.first < nHeight)) {
            return state.DoS(100, false, REJECT_INVALID,
                             "bad-txns-spark-mint-duplicate");
        }
    }

    return true;
}

static bool CheckLTag(
        CValidationState &state,
        CSparkTxInfo *sparkTxInfo,
        const GroupElement& lTag,
        int nHeight,
        bool fConnectTip,
        CSparkState& validationState) {
    // check for Spark transaction in this block as well
    if (sparkTxInfo &&
        !sparkTxInfo->fInfoIsComplete &&
            sparkTxInfo->spentLTags.find(lTag) != sparkTxInfo->spentLTags.end())
        return state.DoS(0, false, REJECT_INVALID,
            "bad-spark-linking-tag-duplicate");

    // check for used linking tags in state
    if (validationState.IsUsedLTag(lTag)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, false, REJECT_INVALID,
                "bad-spark-linking-tag-used");
        }
    }
    return true;
}

bool BuildSparkStateFromIndex(CChain *chain) {
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
    {
        sparkState.AddBlock(blockIndex);
        CSparkNameManager::GetInstance()->AddBlock(blockIndex);
    }
    // DEBUG
    LogPrintf(
            "Latest ID for Spark coin group  %d\n",
            sparkState.GetLatestCoinID());
    return true;
}

// CSparkTxInfo
void CSparkTxInfo::Complete() {
    // We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
    // works, we need to stick to it.
    sort(mints.begin(), mints.end(),
         [](decltype(mints)::const_reference m1, decltype(mints)::const_reference m2)->bool {
             CDataStream ds1(SER_DISK, CLIENT_VERSION), ds2(SER_DISK, CLIENT_VERSION);
             ds1 << m1;
             ds2 << m2;
             return ds1.str() < ds2.str();
         });

    // Mark this info as complete
    fInfoIsComplete = true;
}

bool IsSparkAllowed()
{
    LOCK(cs_main);
    return IsSparkAllowed(chainActive.Height());
}

bool IsSparkAllowed(int height)
{
    return height >= ::Params().GetConsensus().nSparkStartBlock;
}

unsigned char GetNetworkType() {
    if (::Params().GetConsensus().IsMain())
        return ADDRESS_NETWORK_MAINNET;
    else if (::Params().GetConsensus().IsTestnet())
        return ADDRESS_NETWORK_TESTNET;
    else if (::Params().GetConsensus().IsDevnet())
        return ADDRESS_NETWORK_DEVNET;
    else
        return ADDRESS_NETWORK_REGTEST;
}

/*
 * Util functions
 */
size_t CountCoinInBlock(CBlockIndex *index, int id) {
    const auto& pd = index->privacyData();
    auto it = pd.sparkMintedCoins.find(id);
    return it != pd.sparkMintedCoins.end() ? it->second.size() : 0;
}

static int NextBlockHeight(CChain* chain)
{
    return (chain && chain->Tip()) ? chain->Height() + 1 : 0;
}

// After Chaum V2, cover-set hash lookup includes the group's first mint block.
// INT_MAX / negative values are mempool sentinels, not consensus heights.
static bool IncludeFirstBlockSetHash(int height)
{
    if (height < 0 || height == INT_MAX)
        return false;
    return height >= ::Params().GetConsensus().nSparkChaumV2StartBlock;
}

std::vector<unsigned char> GetAnonymitySetHash(CBlockIndex *index, int group_id, bool generation = false, bool includeFirstBlock = false) {
    std::vector<unsigned char> out_hash;

    CSparkState::SparkCoinGroupInfo coinGroup;
    if (!sparkState.GetCoinGroupInfo(group_id, coinGroup))
        return out_hash;

    if ((coinGroup.firstBlock == coinGroup.lastBlock && generation) || (coinGroup.nCoins == 0))
        return out_hash;

    // Pre-V2: stop before firstBlock so one-block groups report an empty hash.
    while (index != coinGroup.firstBlock || includeFirstBlock) {
        const auto& pd = index->privacyData();
        auto it = pd.sparkSetHash.find(group_id);
        if (it != pd.sparkSetHash.end()) {
            out_hash = it->second;
            break;
        }
        if (index == coinGroup.firstBlock)
            break;
        index = index->pprev;
    }
    return out_hash;
}

void ParseSparkMintTransaction(const std::vector<CScript>& scripts, MintTransaction& mintTransaction)
{
    std::vector<CDataStream> serializedCoins;
    for (const auto& script : scripts) {
        if (!script.IsSparkMint())
            throw std::invalid_argument("Script is not a Spark mint");

        std::vector<unsigned char> serialized(script.begin() + 1, script.end());
        size_t size = spark::Coin::memoryRequired() + 8; // 8 is the size of uint64_t
        if (serialized.size() < size) {
            throw std::invalid_argument("Script is not a valid Spark mint");
        }

        CDataStream stream(
                std::vector<unsigned char>(serialized.begin(), serialized.end()),
                SER_NETWORK,
                PROTOCOL_VERSION
        );

        serializedCoins.push_back(stream);
    }
    try {
        mintTransaction.setMintTransaction(serializedCoins);
    } catch (const std::bad_alloc &) {
        throw;
    } catch (const std::exception &) {
        throw std::invalid_argument("Unable to deserialize Spark mint transaction");
    }
}

void ParseSparkMintCoin(const CScript& script, spark::Coin& txCoin)
{
    if (!script.IsSparkMint() && !script.IsSparkSMint())
        throw std::invalid_argument("Script is not a Spark mint");

    if (script.size() < 213) {
        throw std::invalid_argument("Script is not a valid Spark Mint");
    }

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    CDataStream stream(
            std::vector<unsigned char>(serialized.begin(), serialized.end()),
            SER_NETWORK,
            PROTOCOL_VERSION
    );

    try {
        stream >> txCoin;
    } catch (const std::bad_alloc &) {
        throw;
    } catch (const std::exception &) {
        throw std::invalid_argument("Unable to deserialize Spark mint");
    }
}

spark::SpendTransaction ParseSparkSpend(const CTransaction &tx)
{
    if (tx.vin.size() != 1 || tx.vin[0].scriptSig.size() < 1) {
        throw CBadTxIn();
    }
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);

    if (tx.vin[0].scriptSig[0] == OP_SPARKSPEND && tx.nVersion >= 3 &&
        (tx.nType == TRANSACTION_SPARK || tx.nType == TRANSACTION_SPARK_V2)) {
        serialized.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    }
    else {
        throw CBadTxIn();
    }
    const spark::Params* params = spark::Params::get_default();
    const auto version = tx.nType == TRANSACTION_SPARK_V2
        ? SpendTransactionVersion::V2
        : SpendTransactionVersion::V1;
    const std::size_t private_output_count = std::count_if(
        tx.vout.begin(), tx.vout.end(), [](const CTxOut& output) {
            return output.scriptPubKey.IsSparkSMint();
        });
    spark::SpendTransaction spendTransaction(
        params, version, private_output_count);
    serialized >> spendTransaction;
    if (version == SpendTransactionVersion::V2) {
        const std::size_t spendSize =
            tx.vExtraPayload.size() - serialized.size();
        CDataStream canonicalSpend(SER_NETWORK, PROTOCOL_VERSION);
        canonicalSpend << spendTransaction;
        if (canonicalSpend.size() != spendSize ||
            !std::equal(
                canonicalSpend.begin(), canonicalSpend.end(),
                tx.vExtraPayload.begin(),
                [](char left, unsigned char right) {
                    return static_cast<unsigned char>(left) == right;
                })) {
            throw std::invalid_argument(
                "Non-canonical Spark V2 spend payload");
        }

        if (serialized.empty()) {
            if (!spendTransaction.getExtensionCommitment().IsNull()) {
                throw std::invalid_argument(
                    "Missing committed Spark V2 extension");
            }
        } else {
            CSparkNameTxData nameData;
            serialized >> nameData;
            if (!serialized.empty()) {
                throw std::invalid_argument(
                    "Trailing data in Spark V2 extension");
            }

            CDataStream canonicalName(SER_NETWORK, PROTOCOL_VERSION);
            canonicalName << nameData;
            const auto nameBegin = tx.vExtraPayload.begin() + spendSize;
            if (canonicalName.size() != tx.vExtraPayload.size() - spendSize ||
                !std::equal(
                    canonicalName.begin(), canonicalName.end(), nameBegin,
                    [](char left, unsigned char right) {
                        return static_cast<unsigned char>(left) == right;
                    }) ||
                spendTransaction.getExtensionCommitment().IsNull() ||
                spendTransaction.getExtensionCommitment() !=
                    CSparkNameManager::GetSparkNameCommitment(nameData)) {
                throw std::invalid_argument(
                    "Invalid committed Spark V2 extension");
            }
        }
    }
    return spendTransaction;
}

CAmount GetSparkSpendFee(const CTransaction& tx)
{
    const uint64_t fee = ParseSparkSpend(tx).getFee();
    if (fee > static_cast<uint64_t>(MAX_MONEY)) {
        throw std::invalid_argument("Spark spend fee is out of range");
    }
    return static_cast<CAmount>(fee);
}


std::vector<GroupElement> GetSparkUsedTags(const CTransaction &tx)
{
    const spark::Params* params = spark::Params::get_default();

    spark::SpendTransaction spendTransaction(params);
    try {
        spendTransaction = ParseSparkSpend(tx);
    } catch (const std::bad_alloc &) {
        throw;
    } catch (const std::exception &) {
        return std::vector<GroupElement>();
    }

    return  spendTransaction.getUsedLTags();
}

std::vector<spark::Coin> GetSparkMintCoins(const CTransaction &tx)
{
    std::vector<spark::Coin> result;

    if (tx.IsSparkTransaction()) {
        std::vector<unsigned char> serial_context = getSerialContext(tx);
        for (const auto& vout : tx.vout) {
            const auto& script = vout.scriptPubKey;
            if (script.IsSparkMint() || script.IsSparkSMint()) {
                try {
                    spark::Coin coin(Params::get_default());
                    ParseSparkMintCoin(script, coin);
                    coin.setSerialContext(serial_context);
                    result.push_back(coin);
                } catch (const std::bad_alloc &) {
                    throw;
                } catch (const std::exception &) {
                    //Continue
                }
            }
        }
    }

    return result;
}

size_t GetSpendInputs(const CTransaction &tx) {
    return tx.IsSparkSpend() ?
           GetSparkUsedTags(tx).size() : 0;
}

CAmount GetSpendTransparentAmount(const CTransaction& tx) {
    CAmount result = 0;
    if (!tx.IsSparkSpend())
        return 0;

    for (const CTxOut &txout : tx.vout)
        result += txout.nValue;
    return result;
}

bool IsSparkSpendFormatAllowed(const CTransaction& tx, int height)
{
    if (!tx.IsSparkSpend()) {
        return true;
    }

    const auto& consensus = ::Params().GetConsensus();
    if (tx.IsSparkSpendV2()) {
        return height >= consensus.nSparkChaumV2StartBlock;
    }

    const int singleInputActivation = std::min(
        consensus.nSparkSingleInputStartBlock,
        consensus.nSparkChaumV2StartBlock);
    if (height < singleInputActivation) {
        return true;
    }

    try {
        // The deployed V1 layout starts with the input-reference vector size.
        // Inspect only that dimension here: block assembly and reorg cleanup
        // need a cheap format check, while full deserialization is performed
        // by transaction validation.
        CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
        payload.write(
            reinterpret_cast<const char*>(tx.vExtraPayload.data()),
            tx.vExtraPayload.size());
        return ReadCompactSize(payload) == 1;
    } catch (const std::exception&) {
        return false;
    }
}

/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockSpark(
        CValidationState &state,
        const CChainParams &chainparams,
        CBlockIndex *pindexNew,
        const CBlock *pblock,
        bool fJustCheck,
        bool isVerifyDB) {

    bool fBackupRewrittenSparkNames = false;
    
    // Add spark transaction information to index
    if (pblock && pblock->sparkTxInfo) {
        if (!fJustCheck) {
            auto& pd = pindexNew->ensurePrivacyData();
            pd.sparkMintedCoins.clear();
            pd.spentLTags.clear();
            pd.sparkSetHash.clear();
        }

        if (!CheckSparkBlock(state, *pblock, pindexNew->nHeight)) {
            return false;
        }

        BOOST_FOREACH(auto& lTag, pblock->sparkTxInfo->spentLTags) {
            CSparkState& validationState =
                SparkStateForValidation(isVerifyDB);
            if (!CheckLTag(
                    state,
                    pblock->sparkTxInfo.get(),
                    lTag.first,
                    pindexNew->nHeight,
                    !isVerifyDB || activeVerifyDBContext,
                    validationState
            )) {
                return false;
            }
        }

        if (!fJustCheck) {
            auto& pd = pindexNew->ensurePrivacyData();
            BOOST_FOREACH (auto& lTag, pblock->sparkTxInfo->spentLTags) {
                pd.spentLTags.insert(lTag);
                sparkState.AddSpend(lTag.first, lTag.second);
            }
            if (GetBoolArg("-mobile", false)) {
                BOOST_FOREACH (auto& lTag, pblock->sparkTxInfo->ltagTxhash) {
                    pd.ltagTxhash.insert(lTag);
                    sparkState.AddLTagTxHash(lTag.first, lTag.second);
                }
            }
        }
        else {
            if (isVerifyDB && activeVerifyDBContext) {
                activeVerifyDBContext->AddBlock(pindexNew);
            }
            return true;
        }

        CHash256 hash;
        bool updateHash = false;
        const bool includeFirstBlock = IncludeFirstBlockSetHash(pindexNew->nHeight);

        if (!pblock->sparkTxInfo->mints.empty()) {
            sparkState.AddMintsToStateAndBlockIndex(pindexNew, pblock);
            int latestCoinId  = sparkState.GetLatestCoinID();
            // add  coins into hasher, for generating set hash
            updateHash = true;
            // get previous hash of the set, if there is no such, don't write anything
            std::vector<unsigned char> prev_hash = GetAnonymitySetHash(pindexNew->pprev, latestCoinId, true, includeFirstBlock);
            if (!prev_hash.empty())
                hash.Write(prev_hash.data(), 32);
            else {
                if (latestCoinId > 1) {
                    prev_hash = GetAnonymitySetHash(pindexNew->pprev, latestCoinId - 1, true, includeFirstBlock);
                    hash.Write(prev_hash.data(), 32);
                }
            }

            for (auto &coin : pindexNew->ensurePrivacyData().sparkMintedCoins[latestCoinId]) {
                CDataStream serializedCoin(SER_NETWORK, 0);
                serializedCoin << coin;
                std::vector<unsigned char> data(serializedCoin.begin(), serializedCoin.end());
                hash.Write(data.data(), data.size());
            }
        }

        if (!pblock->sparkTxInfo->sparkNames.empty()) {
            CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();

            try {
                for (const auto &sparkName : pblock->sparkTxInfo->sparkNames) {
                    uint8_t opType = sparkName.second.nVersion >= 2 ?
                                                    sparkName.second.operationType : static_cast<uint8_t>(CSparkNameTxData::opRegister);
                    // For V2.1+, renewals and transfers preserve remaining validity
                    int validityBlocks = sparkName.second.sparkNameValidityBlocks;
                    const auto& consensusParams = ::Params().GetConsensus();
                    if (pindexNew->nHeight >= consensusParams.nSparkNamesV21StartBlock) {
                        try {
                            int existingExpirationHeight = sparkNameManager->GetSparkNameBlockHeight(sparkName.first);
                            int remainingBlocks = existingExpirationHeight - pindexNew->nHeight;
                            if (remainingBlocks > 0)
                                validityBlocks += remainingBlocks;
                        } catch (const std::runtime_error&) {
                            // name doesn't exist yet, no adjustment needed
                        }
                    }

                    switch (opType) {
                        case CSparkNameTxData::opRegister:
                            pindexNew->ensurePrivacyData().addedSparkNames[sparkName.first] =
                                CSparkNameBlockIndexData(sparkName.second.name,
                                    sparkName.second.sparkAddress,
                                    pindexNew->nHeight + validityBlocks,
                                    sparkName.second.additionalInfo);
                            break;

                        case CSparkNameTxData::opTransfer:
                            // old name data goes to removed list
                            pindexNew->ensurePrivacyData().removedSparkNames[sparkName.first] =
                                CSparkNameBlockIndexData(sparkName.second.name,
                                    sparkName.second.oldSparkAddress,
                                    sparkNameManager->GetSparkNameBlockHeight(sparkName.first),
                                    sparkNameManager->GetSparkNameAdditionalData(sparkName.first));

                            pindexNew->ensurePrivacyData().addedSparkNames[sparkName.first] =
                                CSparkNameBlockIndexData(sparkName.second.name,
                                    sparkName.second.sparkAddress,
                                    pindexNew->nHeight + validityBlocks,
                                    sparkName.second.additionalInfo);

                            break;

                        case CSparkNameTxData::opUnregister:
                            pindexNew->ensurePrivacyData().removedSparkNames[sparkName.first] =
                                CSparkNameBlockIndexData(sparkName.second.name,
                                    sparkName.second.sparkAddress,
                                    sparkNameManager->GetSparkNameBlockHeight(sparkName.first),
                                    sparkNameManager->GetSparkNameAdditionalData(sparkName.first));
                            break;

                        default:
                            return state.DoS(100, error("ConnectBlockSpark: invalid spark name op type"));
                    }
                }
            }
            catch (const std::exception &) {
                // fatal error, should never happen
                LogPrintf("ConnectBlockSpark: fatal exception when adding spark names to index\n");
                return state.DoS(100, error("ConnectBlockSpark: failed to index spark names"));
            }

            // names were added, backup rewritten names if necessary
            fBackupRewrittenSparkNames = true;
        }

        // generate hash if we need it
        if (updateHash) {
            unsigned char hash_result[CSHA256::OUTPUT_SIZE];
            hash.Finalize(hash_result);
            auto &out_hash = pindexNew->ensurePrivacyData().sparkSetHash[sparkState.GetLatestCoinID()];
            out_hash.clear();
            out_hash.insert(out_hash.begin(), std::begin(hash_result), std::end(hash_result));
        }
    }
    else if (!fJustCheck) {
        sparkState.AddBlock(pindexNew);
    }

    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();

    auto removedNames = sparkNameManager->RemoveSparkNamesLosingValidity(pindexNew->nHeight);
    for (const auto &name: removedNames)
        pindexNew->ensurePrivacyData().removedSparkNames[name.first] = name.second;
    
    sparkNameManager->AddBlock(pindexNew, fBackupRewrittenSparkNames);

    if (!fJustCheck &&
        pindexNew->nHeight + 1 ==
            chainparams.GetConsensus().nSparkChaumV2StartBlock) {
        ClearSparkSpendProofCache();
    }

    return true;
}

void RemoveSpendReferencingBlock(CTxMemPool& pool, CBlockIndex* blockIndex) {
    LOCK2(cs_main, pool.cs);
    std::vector<CTransaction> txn_to_remove;
    for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); ++mi) {
        const CTransaction& tx = mi->GetTx();
        if (tx.IsSparkSpend()) {
            // Run over all the inputs, check if their CoinGroup block hash is equal to
            // block removed. If any one is equal, remove txn from mempool.
            for (const CTxIn& txin : tx.vin) {
                if (txin.scriptSig.IsSparkSpend()) {
                    std::unique_ptr<spark::SpendTransaction> sparkSpend;

                    try {
                        sparkSpend = std::make_unique<spark::SpendTransaction>(ParseSparkSpend(tx));
                    }
                    catch (const std::exception &) {
                        txn_to_remove.push_back(tx);
                        break;
                    }

                    const std::map<uint64_t, uint256>& coinGroupIdAndBlockHash = sparkSpend->getBlockHashes();
                    for(const auto& idAndHash : coinGroupIdAndBlockHash) {
                        if (idAndHash.second == blockIndex->GetBlockHash()) {
                            // Do not remove transaction immediately, that will invalidate iterator mi.
                            txn_to_remove.push_back(tx);
                            break;
                        }
                    }
                }
            }
        }
    }
    for (const CTransaction& tx: txn_to_remove) {
        // Remove txn from mempool.
        pool.removeRecursive(tx);
        LogPrintf("DisconnectTipSpark: removed spark spend which referenced a removed blockchain tip.");
    }
}

void DisconnectTipSpark(CBlock& block, CBlockIndex *pindexDelete) {
    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
    sparkNameManager->RemoveBlock(pindexDelete);

    sparkState.RemoveBlock(pindexDelete);

    // Spark verification depends on active-chain cover-set data. Refresh all
    // cached results after a disconnect so they use the current chain context.
    ClearSparkSpendProofCache();

    // Also remove from mempool spends that reference given block hash.
    RemoveSpendReferencingBlock(mempool, pindexDelete);
    RemoveSpendReferencingBlock(txpools.getStemTxPool(), pindexDelete);
}

bool CheckSparkBlock(CValidationState &state, const CBlock& block, int nBlockHeight) {
    auto& consensus = ::Params().GetConsensus();

    CAmount blockSpendsValue = 0;

    for (const auto& tx : block.vtx) {
        auto txSpendsValue =  GetSpendTransparentAmount(*tx);

        if (txSpendsValue > consensus.GetMaxValueSparkSpendPerTransaction(nBlockHeight)) {
            return state.DoS(100, false, REJECT_INVALID,
                             "bad-txns-spark-spend-invalid");
        }
        blockSpendsValue += txSpendsValue;
    }

    if (cmp::greater(blockSpendsValue, consensus.GetMaxValueSparkSpendPerBlock(nBlockHeight))) {
        return state.DoS(100, false, REJECT_INVALID,
                         "bad-txns-spark-spend-invalid");
    }

    return true;
}


bool CheckSparkMintTransaction(
        const std::vector<CTxOut>& txOuts,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo) {

    LogPrintf("CheckSparkMintTransaction txHash = %s\n", hashTx.GetHex());
    const spark::Params* params = spark::Params::get_default();
    std::vector<CScript> scripts;
    for (const auto& txOut : txOuts) {
        scripts.push_back(txOut.scriptPubKey);
    }

    MintTransaction mintTransaction(params);
    try {
        ParseSparkMintTransaction(scripts, mintTransaction);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CTransaction::CheckTransaction() : SparkMint parsing failure.");
    }

    //checking whether MintTransaction is valid
    if (!mintTransaction.verify()) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSparkMintTransaction : mintTransaction verification failed");
    }
    std::vector<Coin> coins;
    mintTransaction.getCoins(coins);

    if (coins.size() != txOuts.size())
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSparkMintTransaction : mintTransaction parsing failed");


    for (size_t i = 0; i < coins.size(); i++) {
        auto& coin = coins[i];
        if (cmp::not_equal(coin.v, txOuts[i].nValue))
            return state.DoS(100,
                             false,
                             PUBCOIN_NOT_VALIDATE,
                             "CheckSparkMintTransaction : mintTransaction failed, wrong amount");

//        if (coin.v > ::Params().GetConsensus().nMaxValueLelantusMint)
//            return state.DoS(100,
//                             false,
//                             REJECT_INVALID,
//                             "CTransaction::CheckTransaction() : Spark Mint is out of limit.");

    }

    if (sparkTxInfo != NULL && !sparkTxInfo->fInfoIsComplete) {
        sparkTxInfo->mints.insert(
            sparkTxInfo->mints.end(), coins.begin(), coins.end());
        sparkTxInfo->spTransactions.insert(hashTx);
    }

    return true;
}

bool CheckSparkSMintTransaction(
        const std::vector<CTxOut>& vout,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        std::vector<Coin>& out_coins,
        CSparkTxInfo* sparkTxInfo) {

    LogPrintf("CheckSparkSMintTransaction txHash = %s\n", hashTx.ToString());
    for (const auto& out : vout) {
        const auto& script = out.scriptPubKey;
        if (script.IsSparkSMint()) {
            try {
                spark::Coin coin(Params::get_default());
                ParseSparkMintCoin(script, coin);
                out_coins.emplace_back(coin);
            } catch (const std::bad_alloc &) {
                return state.Error(
                    "CheckSparkSMintTransaction: memory allocation failed while parsing output");
            } catch (const std::exception &) {
                return state.DoS(100,
                         false,
                         REJECT_INVALID,
                         "CTransaction::CheckTransaction() : Spark Mint is invalid.");
            }
        }
    }

    for (auto& coin : out_coins) {
        if (sparkTxInfo != NULL && !sparkTxInfo->fInfoIsComplete) {
            // Update coin list in the info
            sparkTxInfo->mints.push_back(coin);
        }
    }

    return true;
}

bool CheckSparkSpendTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo) {

    std::unordered_set<GroupElement, spark::CLTagHash> txLTags;

    if (tx.vin.size() != 1 || !tx.vin[0].scriptSig.IsSparkSpend()) {
        // mixing spark spend input with non-spark inputs is prohibited
        return state.DoS(100, false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: can't mix spark spend input with other tx types or have more than one spend");
    }

    Consensus::Params const & params = ::Params().GetConsensus();
    int height = nHeight == INT_MAX ? chainActive.Height()+1 : nHeight;
    const bool isMempoolAcceptance = !sparkTxInfo && nHeight == INT_MAX;
    const bool isChaumV2 = tx.nType == TRANSACTION_SPARK_V2;
    if (fStatefulSigmaCheck && isMempoolAcceptance && isChaumV2 &&
        height < params.nSparkChaumV2StartBlock) {
        // Do not parse or score a format that cannot enter the next block.
        // This also keeps malformed premature payloads from affecting a peer's
        // ban score before the format is active.
        return state.DoS(
            0,
            false,
            REJECT_NONSTANDARD,
            "CheckSparkSpendTransaction: CHAUM_V2 is not active");
    }
    if (!isVerifyDB) {
            if (height >= params.nSparkStartBlock) {
                // data should be moved to v3 payload
                if (tx.nVersion < 3 ||
                    (tx.nType != TRANSACTION_SPARK &&
                     tx.nType != TRANSACTION_SPARK_V2))
                    return state.DoS(100, false, NSEQUENCE_INCORRECT,
                                     "CheckSparkSpendTransaction: spark data should reside in transaction payload");
            }
    }

    std::shared_ptr<spark::SpendTransaction> spend;

    try {
        spend = std::make_shared<spark::SpendTransaction>(ParseSparkSpend(tx));
    }
    catch (CBadTxIn&) {
        return state.DoS(100,
                         false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: invalid spend transaction");
    }
    catch (const std::bad_alloc &) {
        return state.Error(
            "CheckSparkSpendTransaction: memory allocation failed while parsing spend");
    }
    catch (const std::exception &) {
        return state.DoS(100,
                         false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: failed to deserialize spend");
    }

    uint256 txHashForMetadata;
    // Obtain the hash of the transaction sans the Spark part
    CMutableTransaction txTemp = tx;
    txTemp.vExtraPayload.clear();
    txTemp.vout.erase(
        std::remove_if(
            txTemp.vout.begin(),
            txTemp.vout.end(),
            [](const CTxOut& output) {
                return output.scriptPubKey.IsSparkSMint();
            }),
        txTemp.vout.end());
    txHashForMetadata = txTemp.GetHash();

    LogPrintf("CheckSparkSpendTransaction: tx metadata hash=%s\n", txHashForMetadata.ToString());

    if (!fStatefulSigmaCheck)
        return true;
    if (isChaumV2 && height < params.nSparkChaumV2StartBlock) {
        return state.DoS(isMempoolAcceptance ? 0 : 100,
                         false,
                         isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                         "CheckSparkSpendTransaction: CHAUM_V2 is not active");
    }
    const int singleInputActivation = std::min(
        params.nSparkSingleInputStartBlock,
        params.nSparkChaumV2StartBlock);
    const bool enforceChaumV1SingleInput =
        !isChaumV2 && height >= singleInputActivation;
    const bool enforceCanonicalGroupIds = isMempoolAcceptance ||
        height >= params.nSparkChaumV2StartBlock;

    const bool requireChaumV1SingleInput =
        !isChaumV2 && (isMempoolAcceptance
            ? height >= (singleInputActivation - 10)
            : enforceChaumV1SingleInput);
    // Mempool policy leads consensus by 10 blocks so stale unbound proofs are
    // drained before H2. Consensus itself binds only from H2 onward.
    const bool enforceBoundCoverSetHash = isMempoolAcceptance
        ? height >= (params.nSparkChaumV2StartBlock - 10)
        : height >= params.nSparkChaumV2StartBlock;
    const bool useBoundCoverSetHash =
        height >= params.nSparkChaumV2StartBlock;
    if (requireChaumV1SingleInput &&
        spend->getUsedLTags().size() != 1) {
        return state.DoS(isMempoolAcceptance ? 0 : 100,
                         false,
                         isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                         "CheckSparkSpendTransaction: multi-input Spark spends are disabled");
    }

    const auto& idAndBlockHashes = spend->getBlockHashes();
    const std::vector<uint64_t>& ids = spend->getCoinGroupIds();
    const auto isInvalidGroupId = [](uint64_t id) {
        return id == 0 || id > static_cast<uint64_t>(std::numeric_limits<int32_t>::max());
    };
    if (enforceCanonicalGroupIds &&
        (std::any_of(ids.begin(), ids.end(), isInvalidGroupId) ||
         std::any_of(idAndBlockHashes.begin(), idAndBlockHashes.end(),
                     [&isInvalidGroupId](const auto& item) { return isInvalidGroupId(item.first); }))) {
        return state.DoS(isMempoolAcceptance ? 0 : 100,
                         false,
                         isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                         "CheckSparkSpendTransaction: invalid coin group id");
    }
    const bool enforceExactCoverSetReferences = isMempoolAcceptance ||
        height >= params.nSparkChaumV2StartBlock;
    if (enforceExactCoverSetReferences) {
        bool referencesMatchIds = false;
        if (ids.size() == spend->getUsedLTags().size()) {
            const std::set<uint64_t> uniqueIds(ids.begin(), ids.end());
            referencesMatchIds =
                idAndBlockHashes.size() == uniqueIds.size() &&
                std::equal(
                    uniqueIds.begin(), uniqueIds.end(), idAndBlockHashes.begin(),
                    [](uint64_t id, const auto& item) { return id == item.first; });
        }
        if (!referencesMatchIds) {
            return state.DoS(isMempoolAcceptance ? 0 : 100,
                             false,
                             isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                             "CheckSparkSpendTransaction: invalid cover set references");
        }
    }
    if (spend->getFee() > static_cast<uint64_t>(MAX_MONEY)) {
        return state.DoS(100, false, REJECT_INVALID,
            "CheckSparkSpendTransaction: fee out of range");
    }
    bool passVerify = false;

    uint64_t Vout = 0;
    std::size_t private_num = 0;
    bool sawPrivateOutput = false;
    for (const CTxOut &txout : tx.vout) {
        const auto& script = txout.scriptPubKey;
        if (!script.empty() && script.IsSparkSMint()) {
            private_num++;
            sawPrivateOutput = true;
            if (isChaumV2) {
                if (txout.nValue != 0) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "CheckSparkSpendTransaction: nonzero Spark V2 private output");
                }
                try {
                    spark::Coin coin(Params::get_default());
                    ParseSparkMintCoin(script, coin);
                    CDataStream canonical(SER_NETWORK, PROTOCOL_VERSION);
                    canonical << coin;
                    if (script.size() != canonical.size() + 1 ||
                        !std::equal(
                            canonical.begin(), canonical.end(),
                            script.begin() + 1,
                            [](char left, unsigned char right) {
                                return static_cast<unsigned char>(left) == right;
                            })) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "CheckSparkSpendTransaction: non-canonical Spark V2 private output");
                    }
                } catch (const std::bad_alloc &) {
                    return state.Error(
                        "CheckSparkSpendTransaction: memory allocation failed while parsing output");
                } catch (const std::exception &) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "CheckSparkSpendTransaction: invalid Spark V2 private output");
                }
            }
        } else if (script.IsSparkMint() ||
                script.IsLelantusMint() ||
                script.IsLelantusJMint() ||
                script.IsSigmaMint()) {
            return state.DoS(100, false, REJECT_INVALID,
                "CheckSparkSpendTransaction: incompatible private output type");
        } else {
            if (isChaumV2 && sawPrivateOutput) {
                return state.DoS(100, false, REJECT_INVALID,
                    "CheckSparkSpendTransaction: non-canonical Spark V2 output order");
            }
            if (txout.nValue < 0 ||
                static_cast<uint64_t>(txout.nValue) >
                    std::numeric_limits<uint64_t>::max() - Vout) {
                return state.DoS(100, false, REJECT_INVALID,
                                 "CheckSparkSpendTransaction: transparent output overflow");
            }
            Vout += static_cast<uint64_t>(txout.nValue);
        }
    }

    if (private_num > ::Params().GetConsensus().nMaxSparkOutLimitPerTx) {
        return state.DoS(100, false, REJECT_INVALID,
            "CheckSparkSpendTransaction: too many private outputs");
    }

    std::vector<Coin> out_coins;
    out_coins.reserve(private_num);
    if (!CheckSparkSMintTransaction(tx.vout, state, hashTx, fStatefulSigmaCheck, out_coins, sparkTxInfo))
        return false;
    spend->setOutCoins(out_coins);
    struct CoverSetSource {
        int stateId;
        int previousStateId;
        CBlockIndex* referenceBlock;
        CBlockIndex* firstBlock;
        std::size_t size;
    };
    std::unordered_map<uint64_t, CoverSetSource> coverSetSources;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;

    BatchProofContainer* batchProofContainer = BatchProofContainer::get_instance();
    bool useBatching = batchProofContainer->fCollectProofs && !isVerifyDB && !isCheckWallet && sparkTxInfo && !sparkTxInfo->fInfoIsComplete;

    for (const auto& idAndHash : idAndBlockHashes) {
        const uint64_t wireGroupId = idAndHash.first;

        // Preserve the deployed 32-bit interpretation for historical blocks.
        // Canonical ID rejection is gated on Chaum V2 so this lookup still
        // matches pre-activation spends that wrap at 32 bits.
        const int stateGroupId = static_cast<int32_t>(wireGroupId);
        const int previousStateGroupId = static_cast<int32_t>(wireGroupId - 1);
        CSparkState::SparkCoinGroupInfo coinGroup;
        CSparkState& validationSparkState =
            SparkStateForValidation(isVerifyDB);
        if (!validationSparkState.GetCoinGroupInfo(
                stateGroupId, coinGroup)) {
            return state.DoS(
                isMempoolAcceptance ? 0 : 100,
                false,
                isMempoolAcceptance ? REJECT_NONSTANDARD : NO_MINT_ZEROCOIN,
                "CheckSparkSpendTransaction: no matching cover set");
        }

        CBlockIndex *index = coinGroup.lastBlock;
        // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
        while (index != coinGroup.firstBlock && index->GetBlockHash() != idAndHash.second)
            index = index->pprev;

        const bool unknownReference =
            index->GetBlockHash() != idAndHash.second;
        if (unknownReference &&
            (isMempoolAcceptance || isChaumV2 || enforceChaumV1SingleInput)) {
            // Mempool admission is a non-punitive policy failure. Consensus
            // retains the deployed first-block fallback only for historical
            // V1 blocks before the single-input activation. V2 and later V1
            // validation fail closed.
            return state.DoS(
                isMempoolAcceptance ? 0 : 100,
                false,
                isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                "CheckSparkSpendTransaction: unknown cover-set reference");
        }

        // take the hash from last block of anonymity set
        std::vector<unsigned char> set_hash =
            GetAnonymitySetHash(index, stateGroupId, false, useBoundCoverSetHash);
        CBlockIndex* referenceBlock = index;

        std::size_t set_size = 0;
        // Build a vector with all the public coins with given id before
        // the block on which the spend occurred.
        // This list of public coins is required by function "Verify" of spend.
        while (true) {
            int id = 0;
            if (CountCoinInBlock(index, stateGroupId)) {
                id = stateGroupId;
            } else if (CountCoinInBlock(index, previousStateGroupId)) {
                id = previousStateGroupId;
            }
            if (id) {
                const auto& mintedCoins = index->privacyData().sparkMintedCoins;
                auto minted = mintedCoins.find(id);
                if (minted != mintedCoins.end()) {
                    set_size += minted->second.size();
                }
            }

            if (index == coinGroup.firstBlock)
                break;
            index = index->pprev;
        }

        // After Chaum V2 (and H2-10 for mempool), nonempty cover sets must
        // commit the canonical 32-byte cumulative hash.
        if (enforceBoundCoverSetHash &&
            set_size > 0 &&
            set_hash.size() != CSHA256::OUTPUT_SIZE) {
            return state.DoS(
                isMempoolAcceptance ? 0 : 100,
                false,
                isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                "CheckSparkSpendTransaction: cover set is not bound to a canonical state hash");
        }

        CoverSetData setData;
        setData.cover_set_size = set_size;
        if (!set_hash.empty())
            setData.cover_set_representation = set_hash;
        setData.cover_set_representation.insert(setData.cover_set_representation.end(), txHashForMetadata.begin(), txHashForMetadata.end());

        coverSetSources.emplace(
            wireGroupId,
            CoverSetSource{
                stateGroupId,
                previousStateGroupId,
                referenceBlock,
                coinGroup.firstBlock,
                set_size});
        cover_set_data[wireGroupId] = setData;
    }
    spend->setCoverSets(cover_set_data);
    spend->setVout(Vout);

    for (const auto& id : ids) {
        if (!coverSetSources.count(id) || !cover_set_data.count(id))
            return state.DoS(
                isMempoolAcceptance ? 0 : 100,
                error("CheckSparkSpendTransaction: No cover set found."),
                isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                "bad-spark-cover-set-missing");
    }

    std::vector<Coin> loadedCoverSet;
    const SpendTransaction::CoverSetProvider coverSetProvider =
        [&coverSetSources, &loadedCoverSet](uint64_t wireId)
            -> const std::vector<Coin>& {
        const auto source = coverSetSources.find(wireId);
        if (source == coverSetSources.end()) {
            throw std::invalid_argument("Cover set missing");
        }

        loadedCoverSet.clear();
        loadedCoverSet.reserve(source->second.size);
        CBlockIndex* index = source->second.referenceBlock;
        while (true) {
            int id = 0;
            if (CountCoinInBlock(index, source->second.stateId)) {
                id = source->second.stateId;
            } else if (CountCoinInBlock(
                    index, source->second.previousStateId)) {
                id = source->second.previousStateId;
            }
            const auto& mintedCoins = index->privacyData().sparkMintedCoins;
            const auto coinsIt = mintedCoins.find(id);
            if (id && coinsIt != mintedCoins.end()) {
                const auto& coins = coinsIt->second;
                loadedCoverSet.insert(
                    loadedCoverSet.end(), coins.begin(), coins.end());
            }
            if (index == source->second.firstBlock) {
                break;
            }
            index = index->pprev;
        }
        if (loadedCoverSet.size() != source->second.size) {
            throw std::invalid_argument("Cover set size changed");
        }
        return loadedCoverSet;
    };
    
    // if we are collecting proofs, skip verification and collect proofs
    // add proofs into container
    if (useBatching) {
        passVerify = true;
        if (isChaumV2 || requireChaumV1SingleInput) {
            batchProofContainer->add(*spend, hashTx);
        } else {
            batchProofContainer->addHistorical(*spend, hashTx);
        }
    } else {
        try {
            bool haveCachedSuccess = false;
            // The cache is txid-only. VerifyDB reconstructs cover sets at the
            // historical height, so a mempool success must not skip re-verify.
            if (!isVerifyDB) {
                LOCK(cs_checkedSparkSpendTransactions);
                haveCachedSuccess = gCheckedSparkSpendTransactions.exists(hashTx);
            }
            if (haveCachedSuccess) {
                LogPrintf("CheckSparkSpendTransaction: already checked tx %s\n", hashTx.ToString());
                passVerify = true;
            }
            else if (isMempoolAcceptance) {
                passVerify = spark::SpendTransaction::verify(
                    spark::Params::get_default(),
                    {*spend},
                    coverSetProvider);
                if (passVerify) {
                    LOCK(cs_checkedSparkSpendTransactions);
                    gCheckedSparkSpendTransactions.insert(hashTx, true);
                }
            }
            else {
                // we need the answer now, so verify and execute
                passVerify = (isChaumV2 || requireChaumV1SingleInput)
                    ? spark::SpendTransaction::verify(
                        spark::Params::get_default(),
                        {*spend},
                        coverSetProvider)
                    : spark::SpendTransaction::verifyHistorical(
                        spark::Params::get_default(),
                        {*spend},
                        coverSetProvider);
            }
        }
        catch (const std::bad_alloc &) {
            return state.Error(
                "CheckSparkSpendTransaction: memory allocation failed while verifying spend");
        }
        catch (const std::exception &) {
            passVerify = false;
        }
    }

    if (passVerify) {
        const std::vector<GroupElement>& lTags = spend->getUsedLTags();

        if (lTags.size() != ids.size()) {
            return state.DoS(100,
                             error("CheckSparkSpendTransaction: size of lTags and group ids don't match."));
        }

        // do not check for duplicates in case we've seen exact copy of this tx in this block before
        if (!(sparkTxInfo && sparkTxInfo->spTransactions.count(hashTx) > 0)) {
            const bool fConnectTip = sparkTxInfo &&
                (!isVerifyDB || activeVerifyDBContext);
            CSparkState& validationSparkState =
                SparkStateForValidation(isVerifyDB);
            for (size_t i = 0; i < lTags.size(); ++i) {
                    if (!CheckLTag(
                            state,
                            sparkTxInfo,
                            lTags[i],
                            nHeight,
                            fConnectTip,
                            validationSparkState)) {
                        LogPrintf("CheckSparkSpendTransaction: lTag check failed, ltag=%s\n", lTags[i]);
                        return false;
                    }
            }
        }

        // check duplicated linking tags in same transaction.
        for (const auto &lTag : lTags) {
            if (!txLTags.insert(lTag).second) {
                return state.DoS(100,
                                 error("CheckSparkSpendTransaction: two or more spends with same linking tag in the same transaction"));
            }
        }

        if (!isCheckWallet) {
            // add spend information to the index
            if (sparkTxInfo && !sparkTxInfo->fInfoIsComplete) {
                for (size_t i = 0; i < lTags.size(); i++) {
                    sparkTxInfo->spentLTags.insert(std::make_pair(
                        lTags[i], static_cast<int32_t>(ids[i])));
                    if (GetBoolArg("-mobile", false)) {
                        sparkTxInfo->ltagTxhash.insert(std::make_pair(primitives::GetLTagHash(lTags[i]), hashTx));
                    }
                }
            }
        }
    }
    else {
        LogPrintf("CheckSparkSpendTransaction: verification failed at block %d\n", nHeight);
        return state.DoS(100, false, REJECT_INVALID,
            "CheckSparkSpendTransaction: proof verification failed");
    }

    if (!isCheckWallet) {
        if (sparkTxInfo && !sparkTxInfo->fInfoIsComplete) {
            sparkTxInfo->spTransactions.insert(hashTx);
        }
    }

    return true;
}

bool CheckSparkTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo)
{
    Consensus::Params const & consensus = ::Params().GetConsensus();

    int nRealHeight = nHeight;
    if (nRealHeight == INT_MAX) {
        LOCK(cs_main);
        nRealHeight = chainActive.Height() + 1;
    }

    bool const allowSpark = IsSparkAllowed(nRealHeight);

    // Check Spark Mint Transaction
    if (allowSpark && tx.IsSparkMint()) {
        std::vector<CTxOut> txOuts;
        for (const CTxOut &txout : tx.vout) {
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsSparkMint()) {
                txOuts.push_back(txout);
            }
        }
        if (!txOuts.empty()) {
            try {
                if (!CheckSparkMintTransaction(
                        txOuts,
                        state,
                        hashTx,
                        fStatefulSigmaCheck,
                        sparkTxInfo)) {
                    LogPrintf("CheckSparkTransaction::Mint verification failed.\n");
                    return false;
                }
            }
            catch (const std::exception &x) {
                return state.Error(x.what());
            }
        } else {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "bad-txns-mint-invalid");
        }
    }

    // Check Spark Spend
    if (tx.IsSparkSpend()) {
        if (GetSpendTransparentAmount(tx) > consensus.GetMaxValueSparkSpendPerTransaction(nRealHeight)) {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "bad-txns-spend-invalid");
        }

        try {
            if (!CheckSparkSpendTransaction(
                    tx, state, hashTx, isVerifyDB, nHeight,
                    isCheckWallet, fStatefulSigmaCheck, sparkTxInfo)) {
                return false;
            }

            if (!isVerifyDB || activeVerifyDBContext) {
                CSparkNameManager *sparkNameManager =
                    SparkNameManagerForValidation(isVerifyDB);
                CSparkNameTxData sparkTxData;
                if (sparkNameManager->CheckSparkNameTx(
                        tx,
                        nRealHeight,
                        state,
                        &sparkTxData,
                        /* nContextualFailureDoS */ nHeight == INT_MAX ? 0 : 100)) {
                    if (!sparkTxData.name.empty() && sparkTxInfo && !sparkTxInfo->fInfoIsComplete) {
                        // Check if the block already contains conflicting spark name
                        if (CSparkNameManager::IsInConflict(sparkTxData, sparkTxInfo->sparkNames,
                                [=](decltype(sparkTxInfo->sparkNames)::const_iterator it)->std::string {
                                    return it->second.sparkAddress;
                                }))
                            return false;

                        sparkTxInfo->sparkNames[CSparkNameManager::ToUpper(sparkTxData.name)] = sparkTxData;
                    }
                }
                else {
                    return false;
                }
            }
        }
        catch (const std::bad_alloc &) {
            return state.Error(
                "CheckSparkTransaction: memory allocation failed while checking spend");
        }
        catch (const std::exception &x) {
            return state.Error(x.what());
        }
    }

    return true;
}

uint256 GetTxHashFromCoin(const spark::Coin& coin) {
    COutPoint outPoint;
    GetOutPoint(outPoint, coin);
    return  outPoint.hash;
}

bool GetOutPoint(COutPoint& outPoint, const spark::Coin& coin)
{
    spark::CSparkState *sparkState = spark::CSparkState::GetState();
    auto mintedCoinHeightAndId = sparkState->GetMintedCoinHeightAndId(coin);
    int mintHeight = mintedCoinHeightAndId.first;
    int coinId = mintedCoinHeightAndId.second;

    if (mintHeight==-1 && coinId==-1)
        return false;

    // get block containing mint
    CBlockIndex *mintBlock = chainActive[mintHeight];
    CBlock block;
    //TODO levon, try to optimize this
    if (!ReadBlockFromDisk(block, mintBlock, ::Params().GetConsensus())) {
        LogPrintf("can't read block from disk.\n");
        return false;
    }

    return GetOutPointFromBlock(outPoint, coin, block);
}

bool GetOutPoint(COutPoint& outPoint, const uint256& coinHash)
{
    spark::Coin coin(Params::get_default());
    spark::CSparkState *sparkState = spark::CSparkState::GetState();
    if (!sparkState->HasCoinHash(coin, coinHash)) {
        return false;
    }

    return GetOutPoint(outPoint, coin);
}

bool GetOutPointFromBlock(COutPoint& outPoint, const spark::Coin& coin, const CBlock &block) {
    spark::Coin txCoin(coin.params);
    // cycle transaction hashes, looking for this coin
    for (CTransactionRef tx : block.vtx){
        uint32_t nIndex = 0;
        for (const CTxOut &txout : tx->vout) {
            if (txout.scriptPubKey.IsSparkMint() || txout.scriptPubKey.IsSparkSMint()) {
                try {
                    ParseSparkMintCoin(txout.scriptPubKey, txCoin);
                }
                catch (const std::exception &) {
                    continue;
                }
                if (coin == txCoin) {
                    outPoint = COutPoint(tx->GetHash(), nIndex);
                    return true;
                }
            }
            nIndex++;
        }
    }
    return false;
}

std::vector<unsigned char> getSerialContext(const CTransaction &tx) {
    CDataStream serialContextStream(SER_NETWORK, PROTOCOL_VERSION);
    if (tx.IsSparkSpend()) {
        try {
            spark::SpendTransaction spend = ParseSparkSpend(tx);
            serialContextStream << spend.getUsedLTags();
        } catch (const std::bad_alloc &) {
            throw;
        } catch (const std::exception &) {
            return std::vector<unsigned char>();
        }
    } else {
        for (auto input: tx.vin) {
            input.scriptSig.clear();
            serialContextStream << input;
        }
    }

    std::vector<unsigned char> serial_context(serialContextStream.begin(), serialContextStream.end());
    return serial_context;
}

FIRO_UNUSED static bool CheckSparkSpendTAg(
        CValidationState& state,
        CSparkTxInfo* sparkTxInfo,
        const GroupElement& tag,
        int nHeight,
        bool fConnectTip) {
    // check for spark transaction in this block as well
    if (sparkTxInfo &&
        !sparkTxInfo->fInfoIsComplete &&
        sparkTxInfo->spentLTags.find(tag) != sparkTxInfo->spentLTags.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spark spends with same tag in the same block"));

    // check for used tags in sparkState
    if (sparkState.IsUsedLTag(tag)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The Spark spend tag has been used"));
        }
    }
    return true;
}

/******************************************************************************/
// CSparkState
/******************************************************************************/

CSparkState::CSparkState(
        size_t maxCoinInGroup,
        size_t startGroupSize)
        :
        maxCoinInGroup(maxCoinInGroup),
        startGroupSize(startGroupSize),
        latestCoinId(0)
{
}

void CSparkState::CopyFrom(const CSparkState& other)
{
    std::unordered_map<spark::Coin, CMintedCoinInfo, spark::CoinHash> coins;
    {
        LOCK(other.cs_minted_coins);
        coins = other.mintedCoins;
    }

    LOCK(cs_minted_coins);
    maxCoinInGroup = other.maxCoinInGroup;
    startGroupSize = other.startGroupSize;
    latestCoinId = other.latestCoinId;
    coinGroups = other.coinGroups;
    mintedCoins = std::move(coins);
    usedLTags = other.usedLTags;
    mobileUsedLTags = other.mobileUsedLTags;
    ltagTxhash = other.ltagTxhash;
    extendedMintMetaInfo = other.extendedMintMetaInfo;
    mintMetaInfo = other.mintMetaInfo;
    spendMetaInfo = other.spendMetaInfo;
}

void CSparkState::Reset() {
    ClearSparkSpendProofCache();
    ShutdownWallet();
    coinGroups.clear();
    latestCoinId = 0;
    {
        LOCK(cs_minted_coins);
        mintedCoins.clear();
    }
    usedLTags.clear();
    mobileUsedLTags.clear();
    mintMetaInfo.clear();
    spendMetaInfo.clear();
}

std::pair<int, int> CSparkState::GetMintedCoinHeightAndId(const spark::Coin& coin) {
    LOCK(cs_minted_coins);
    auto coinIt = mintedCoins.find(coin);

    if (coinIt != mintedCoins.end()) {
        return std::make_pair(coinIt->second.nHeight, coinIt->second.coinGroupId);
    }
    return std::make_pair(-1, -1);
}

bool CSparkState::HasCoin(const spark::Coin& coin) {
    LOCK(cs_minted_coins);
    return mintedCoins.find(coin) != mintedCoins.end();

}

bool CSparkState::HasCoinHash(spark::Coin& coin, const uint256& coinHash) {
    LOCK(cs_minted_coins);
    for (auto it = mintedCoins.begin(); it != mintedCoins.end(); ++it ){
        const spark::Coin& coin_ = (*it).first;
        if (primitives::GetSparkCoinHash(coin_) == coinHash) {
            coin = coin_;
            return true;
        }
    }
    return false;
}

bool CSparkState::GetCoinGroupInfo(
        int group_id,
        SparkCoinGroupInfo& result) {
    if (coinGroups.count(group_id) == 0)
        return false;

    result = coinGroups[group_id];
    return true;
}

int CSparkState::GetLatestCoinID() const {
    return latestCoinId;
}

bool CSparkState::IsUsedLTag(const GroupElement& lTag) {
    return usedLTags.count(lTag) != 0;
}

bool CSparkState::IsUsedLTagHash(GroupElement& lTag, const uint256 &coinLTaglHash) {
    for ( auto it = GetSpends().begin(); it != GetSpends().end(); ++it ) {
        if (primitives::GetLTagHash(it->first) == coinLTaglHash) {
            lTag = it->first;
            return true;
        }
    }
    return false;
}


bool CSparkState::CanAddSpendToMempool(const GroupElement& lTag) {
    LOCK(mempool.cs);
    return !IsUsedLTag(lTag) && !mempool.sparkState.HasLTag(lTag);
}

bool CSparkState::CanAddMintToMempool(const spark::Coin& coin){
    LOCK(mempool.cs);
    return !HasCoin(coin) && !mempool.sparkState.HasMint(coin);
}

bool CSparkState::AddMint(
        const spark::Coin& coin,
        const CMintedCoinInfo& coinInfo) {
    LOCK(cs_minted_coins);
    const auto inserted = mintedCoins.emplace(coin, coinInfo).second;
    if (inserted) {
        mintMetaInfo[coinInfo.coinGroupId] += 1;
    }
    return inserted;
}

bool CSparkState::RemoveMint(
        const spark::Coin& coin,
        int expectedGroupId,
        int expectedHeight) {
    LOCK(cs_minted_coins);

    auto iter = mintedCoins.find(coin);
    if (iter == mintedCoins.end() ||
            iter->second.coinGroupId != expectedGroupId ||
            iter->second.nHeight != expectedHeight) {
        return false;
    }

    auto metaIt = mintMetaInfo.find(expectedGroupId);
    if (metaIt != mintMetaInfo.end() && metaIt->second > 0) {
        --metaIt->second;
    }

    mintedCoins.erase(iter);
    return true;
}

void CSparkState::AddMintsToStateAndBlockIndex(
        CBlockIndex *index,
        const CBlock* pblock) {

    std::vector<spark::Coin> blockMints = pblock->sparkTxInfo->mints;
    latestCoinId = std::max(1, latestCoinId);
    auto &coinGroup = coinGroups[latestCoinId];

    if (coinGroup.nCoins + blockMints.size() <= maxCoinInGroup) {
        if (coinGroup.nCoins == 0) {
            // first group of coins
            assert(coinGroup.firstBlock == nullptr);
            assert(coinGroup.lastBlock == nullptr);

            coinGroup.firstBlock = coinGroup.lastBlock = index;
        } else {
            assert(coinGroup.firstBlock != nullptr);
            assert(coinGroup.lastBlock != nullptr);
            assert(coinGroup.lastBlock->nHeight <= index->nHeight);

            coinGroup.lastBlock = index;
        }
        coinGroup.nCoins += blockMints.size();
    } else {
        auto& newCoinGroup = coinGroups[++latestCoinId];

        CBlockIndex *first;
        auto coins = CountLastNCoins(latestCoinId - 1, startGroupSize, first);
        newCoinGroup.firstBlock = first ? first : index;
        newCoinGroup.lastBlock = index;
        newCoinGroup.nCoins = coins + blockMints.size();
    }

    for (const auto& mint : blockMints) {
        const bool inserted = AddMint(
            mint, CMintedCoinInfo::make(latestCoinId, index->nHeight));
        LogPrintf(
            "AddMintsToStateAndBlockIndex: Spark mint %s id=%d\n",
            inserted ? "added" : "already present",
            latestCoinId);
        auto& pd = index->ensurePrivacyData();
        pd.sparkMintedCoins[latestCoinId].push_back(mint);
        if (GetBoolArg("-mobile", false)) {
            COutPoint outPoint;
            GetOutPointFromBlock(outPoint, mint, *pblock);
            CTransactionRef tx;
            for (CTransactionRef itr : pblock->vtx) {
                if (outPoint.hash == itr->GetHash())
                    tx = itr;
            }
            pd.sparkTxHashContext[mint.S] = {outPoint.hash, getSerialContext(*tx)};
        }
    }
}

void CSparkState::AddSpend(const GroupElement& lTag, int coinGroupId) {
    if (mintMetaInfo.count(coinGroupId) > 0) {
        usedLTags[lTag] = coinGroupId;
        if (GetBoolArg("-mobile", false)) {
            mobileUsedLTags.push_back({lTag, coinGroupId});
        }
        spendMetaInfo[coinGroupId] += 1;
    }
}

void CSparkState::AddLTagTxHash(const uint256& lTagHash, const uint256& txHash) {
    ltagTxhash[lTagHash] = txHash;
}

void CSparkState::RemoveSpend(const GroupElement& lTag) {
    auto iter = usedLTags.find(lTag);
    if (GetBoolArg("-mobile", false) && iter != usedLTags.end()) {
        for (auto tag = mobileUsedLTags.begin(); tag != mobileUsedLTags.end(); tag++) {
            if (tag->first == lTag) {
                mobileUsedLTags.erase(tag);
                break;
            }
        }
    }
    if (iter != usedLTags.end()) {
        spendMetaInfo[iter->second] -= 1;
        usedLTags.erase(iter);
    }
}

void CSparkState::AddBlock(CBlockIndex *index) {
    const auto& pd = index->privacyData();
    for (auto const& coins : pd.sparkMintedCoins) {
        if (coins.second.empty())
            continue;

        auto &coinGroup = coinGroups[coins.first];

        if (coinGroup.firstBlock == nullptr) {
            coinGroup.firstBlock = index;

            if (coins.first > 1) {
                CBlockIndex *first;
                coinGroup.nCoins = CountLastNCoins(coins.first - 1, startGroupSize, first);
                coinGroup.firstBlock = first ? first : index;
            }
        }
        coinGroup.lastBlock = index;
        coinGroup.nCoins += coins.second.size();

        latestCoinId = coins.first;
        for (auto const &coin : coins.second) {
            AddMint(coin, CMintedCoinInfo::make(coins.first, index->nHeight));
        }
    }

    for (auto const &lTags : pd.spentLTags) {
        AddSpend(lTags.first, lTags.second);
    }
    if (GetBoolArg("-mobile", false)) {
        for (auto const &elem : pd.ltagTxhash) {
            AddLTagTxHash(elem.first, elem.second);
        }
    }
}

void CSparkState::RemoveBlock(CBlockIndex *index) {
    // roll back coin group updates
    const auto& pd = index->privacyData();
    for (auto &coins : pd.sparkMintedCoins)
    {
        if (coinGroups.count(coins.first) == 0)
            continue;

        SparkCoinGroupInfo& coinGroup = coinGroups[coins.first];
        auto nMintsToForget = coins.second.size();

        if (nMintsToForget == 0)
            continue;

        assert(cmp::greater_equal(coinGroup.nCoins, nMintsToForget));
        auto isExtended = coins.first > 1;
        coinGroup.nCoins -= nMintsToForget;

        // if `index` is edged block we need to erase group
        auto isEdgedBlock = false;
        if (isExtended) {
            auto prevBlockContainMints = index;
            size_t prevGroupCount = 0;

            // find block that contain some Spark mints
            do {
                prevBlockContainMints = prevBlockContainMints->pprev;
            } while (prevBlockContainMints
                     && CountCoinInBlock(prevBlockContainMints, coins.first) == 0
                     && (prevGroupCount = CountCoinInBlock(prevBlockContainMints, coins.first - 1)) == 0);

            isEdgedBlock = prevGroupCount > 0 && (coinGroup.nCoins - prevGroupCount) < startGroupSize;
        }

        if ((!isExtended && coinGroup.nCoins == 0) || (isExtended && isEdgedBlock)) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(coins.first);
            // decrease pubcoin id
            latestCoinId--;
        } else {
            // roll back lastBlock to previous position
            assert(coinGroup.lastBlock == index);

            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->privacyData().sparkMintedCoins.count(coins.first) == 0);
        }
    }

    // roll back mints
    for (auto const&coins : pd.sparkMintedCoins) {
        for (auto const& coin : coins.second) {
            // A legacy index may contain a duplicate that never entered
            // mintedCoins. Height/group must match so an older occurrence stays.
            RemoveMint(coin, coins.first, index->nHeight);
        }
    }

    // roll back spends
    for (auto const& lTag : pd.spentLTags) {
        RemoveSpend(lTag.first);
    }
}

bool CSparkState::AddSpendToMempool(const std::vector<GroupElement>& lTags, uint256 txHash) {
    LOCK(mempool.cs);
    for (const auto& lTag : lTags){
        if (IsUsedLTag(lTag) || mempool.sparkState.HasLTag(lTag))
            return false;

        mempool.sparkState.AddSpendToMempool(lTag, txHash);
    }

    return true;
}

void CSparkState::RemoveSpendFromMempool(const std::vector<GroupElement>& lTags) {
    LOCK(mempool.cs);
    for (const auto& lTag : lTags) {
        mempool.sparkState.RemoveSpendFromMempool(lTag);
    }
}

void CSparkState::AddMintsToMempool(
        const std::vector<spark::Coin>& coins,
        const uint256& txHash) {
    LOCK(mempool.cs);
    for (const auto& coin : coins) {
        mempool.sparkState.AddMintToMempool(coin, txHash);
    }
}

void CSparkState::RemoveMintFromMempool(const spark::Coin& coin) {
    LOCK(mempool.cs);
    mempool.sparkState.RemoveMintFromMempool(coin);
}

uint256 CSparkState::GetMempoolConflictingTxHash(const GroupElement& lTag) {
    LOCK(mempool.cs);
    return mempool.sparkState.GetMempoolConflictingTxHash(lTag);
}

CSparkState* CSparkState::GetState() {
    return &sparkState;
}

void CSparkState::GetCoinSet(
        int coinGroupID,
        std::vector<spark::Coin>& coins_out) {
    int maxHeight;
    uint256 blockHash;
    std::vector<unsigned char> setHash;
    {
        FIRO_UNUSED const auto &params = ::Params().GetConsensus();
        LOCK(cs_main);
        maxHeight = chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1);
    }
    GetCoinSetForSpend(
            &chainActive,
            maxHeight,
            coinGroupID,
            blockHash,
            coins_out,
            setHash);
}

int CSparkState::GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        uint256& blockHash_out,
        std::vector<spark::Coin>& coins_out,
        std::vector<unsigned char>& setHash_out) {

    coins_out.clear();

    if (coinGroups.count(coinGroupID) == 0) {
        return 0;
    }

    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    coins_out.reserve(coinGroup.nCoins);
    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {

        // ignore block heigher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }

        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }

        if (id) {
            if (numberOfCoins == 0) {
                // latest block satisfying given conditions
                // remember block hash and set hash
                blockHash_out = block->GetBlockHash();
                setHash_out =  GetAnonymitySetHash(block, id, false, IncludeFirstBlockSetHash(NextBlockHeight(chain)));
            }
            const auto& bpd = block->privacyData();
            auto it = bpd.sparkMintedCoins.find(id);
            if (it != bpd.sparkMintedCoins.end()) {
                numberOfCoins += it->second.size();
                for (const auto &coin : it->second)
                    coins_out.push_back(coin);
            }
        }

        if (block == coinGroup.firstBlock) {
            break ;
        }
    }

    return numberOfCoins;
}

void CSparkState::GetCoinsForRecovery(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        std::string start_block_hash,
        uint256& blockHash_out,
        std::vector<std::pair<spark::Coin, std::pair<uint256, std::vector<unsigned char>>>>& coins,
        std::vector<unsigned char>& setHash_out) {
    coins.clear();
    if (coinGroups.count(coinGroupID) == 0) {
        return;
    }
    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {
        // ignore block heigher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }
        if (block->GetBlockHash().GetHex() == start_block_hash) {
            break;
        }
        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }
        if (id) {
            if (numberOfCoins == 0) {
                // latest block satisfying given conditions
                // remember block hash and set hash
                blockHash_out = block->GetBlockHash();
                setHash_out =  GetAnonymitySetHash(block, id, false, IncludeFirstBlockSetHash(NextBlockHeight(chain)));
            }
            const auto& bpd = block->privacyData();
            auto it = bpd.sparkMintedCoins.find(id);
            if (it != bpd.sparkMintedCoins.end()) {
                numberOfCoins += it->second.size();
                for (const auto &coin : it->second) {
                    std::pair<uint256, std::vector<unsigned char>> txHashContext;
                    auto ctx = bpd.sparkTxHashContext.find(coin.S);
                    if (ctx != bpd.sparkTxHashContext.end())
                        txHashContext = ctx->second;
                    coins.push_back({coin, txHashContext});
                }
            }
        }
        if (block == coinGroup.firstBlock) {
            break ;
        }
    }
}

void CSparkState::GetAnonSetMetaData(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        uint256& blockHash_out,
        std::vector<unsigned char>& setHash_out,
        int& size) {
    if (coinGroups.count(coinGroupID) == 0) {
        return;
    }
    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    size = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {
        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }
        if (id) {
            if (size == 0) {
                // latest block satisfying given conditions
                // remember block hash and set hash
                blockHash_out = block->GetBlockHash();
                setHash_out =  GetAnonymitySetHash(block, id, false, IncludeFirstBlockSetHash(NextBlockHeight(chain)));
            }
            auto it = block->privacyData().sparkMintedCoins.find(id);
            if (it != block->privacyData().sparkMintedCoins.end())
                size += it->second.size();
        }
        if (block == coinGroup.firstBlock) {
            break ;
        }
    }
}

void CSparkState::GetCoinsForRecovery(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        int startIndex,
        int endIndex,
        uint256& blockHash,
        std::vector<std::pair<spark::Coin, std::pair<uint256, std::vector<unsigned char>>>>& coins) {
    coins.clear();
    if (coinGroups.count(coinGroupID) == 0) {
        throw std::runtime_error(std::string("There is no anonymity set with this id: " + std::to_string(coinGroupID)));
    }
    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    CBlockIndex *index = coinGroup.lastBlock;
    // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
    while (index != coinGroup.firstBlock && index->GetBlockHash() != blockHash)
        index = index->pprev;

    if (index == coinGroup.firstBlock && coinGroup.firstBlock != coinGroup.lastBlock)
        throw std::runtime_error(std::string("Incorrect blockHash provided: " + blockHash.GetHex()));

    std::size_t counter = 0;
    for (CBlockIndex *block = index;; block = block->pprev) {
        // ignore block heigher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }

        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }
        if (id) {
            const auto& bpd = block->privacyData();
            auto it = bpd.sparkMintedCoins.find(id);
            if (it != bpd.sparkMintedCoins.end()) {
                for (const auto &coin : it->second) {
                    if (cmp::less(counter, startIndex)) {
                        ++counter;
                        continue;
                    }
                    if (cmp::greater_equal(counter, endIndex)) {
                        break;
                    }
                    std::pair<uint256, std::vector<unsigned char>> txHashContext;
                    auto ctx = bpd.sparkTxHashContext.find(coin.S);
                    if (ctx != bpd.sparkTxHashContext.end())
                        txHashContext = ctx->second;
                    coins.push_back({coin, txHashContext});
                    ++counter;
                }
            }
        }
        if (block == coinGroup.firstBlock || cmp::greater_equal(counter, endIndex)) {
            break ;
        }
    }
}

std::unordered_map<spark::Coin, CMintedCoinInfo, spark::CoinHash> CSparkState::GetMints() const {
    LOCK(cs_minted_coins);
    return mintedCoins;
}

std::size_t CSparkState::GetTotalCoins() const {
    LOCK(cs_minted_coins);
    return mintedCoins.size();
}

std::unordered_map<GroupElement, int, spark::CLTagHash> const & CSparkState::GetSpends() const {
    return usedLTags;
}

std::vector<std::pair<GroupElement, int>> const & CSparkState::GetSpendsMobile() const {
    return mobileUsedLTags;
}

std::unordered_map<uint256, uint256> const& CSparkState::GetSpendTxIds() const {
    return ltagTxhash;
}

std::unordered_map<int, CSparkState::SparkCoinGroupInfo> const& CSparkState::GetCoinGroups() const {
    return coinGroups;
}

std::unordered_map<GroupElement, uint256, spark::CLTagHash> const& CSparkState::GetMempoolLTags() const {
    LOCK(mempool.cs);
    return mempool.sparkState.GetMempoolLTags();
}

// private
size_t CSparkState::CountLastNCoins(int groupId, size_t required, CBlockIndex* &first) {
    first = nullptr;
    size_t coins = 0;

    if (coinGroups.count(groupId)) {
        auto &group = coinGroups[groupId];

        for (auto block = group.lastBlock
                ; coins < required && block
                ; block = block->pprev) {

            size_t inBlock;
            auto it = block->privacyData().sparkMintedCoins.find(groupId);
            if (it != block->privacyData().sparkMintedCoins.end()
                && (inBlock = it->second.size())) {

                coins += inBlock;
                first = block;
            }
        }
    }

    return coins;
}


// CSparkMempoolState
bool CSparkMempoolState::HasMint(const spark::Coin& coin) {
    return mempoolMints.count(coin.getHash()) > 0;
}

void CSparkMempoolState::AddMintToMempool(const spark::Coin& coin, const uint256& txHash) {
    mempoolMints.emplace(coin.getHash(), txHash);
}

void CSparkMempoolState::RemoveMintFromMempool(const spark::Coin& coin) {
    mempoolMints.erase(coin.getHash());
}

uint256 CSparkMempoolState::GetMempoolConflictingMintTxHash(const spark::Coin& coin) {
    const auto it = mempoolMints.find(coin.getHash());
    return it == mempoolMints.end() ? uint256() : it->second;
}

bool CSparkMempoolState::HasLTag(const GroupElement& lTag) {
    return mempoolLTags.count(lTag) > 0;
}

bool CSparkMempoolState::AddSpendToMempool(const GroupElement& lTag, uint256 txHash) {
    return mempoolLTags.insert({lTag, txHash}).second;
}

void CSparkMempoolState::RemoveSpendFromMempool(const GroupElement& lTag) {
    mempoolLTags.erase(lTag);
}

uint256 CSparkMempoolState::GetMempoolConflictingTxHash(const GroupElement& lTag) {
    if (mempoolLTags.count(lTag) == 0)
        return uint256();

    return mempoolLTags[lTag];
}

void CSparkMempoolState::Reset() {
    mempoolLTags.clear();
    mempoolMints.clear();
}

} // namespace spark
