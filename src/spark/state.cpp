#include "threadpool.h"
#include "state.h"
#include "compat_layer.h"
#include "sparkname.h"
#include "sparkasset.h"
#include "../hash.h"
#include "../validation.h"
#include "../base58.h"
#include "../coins.h"
#include "../script/interpreter.h"
#include "../script/standard.h"
#include "../txmempool.h"
#include "../batchproof_container.h"
#include "../libspark/keys.h"
#include "../libspark/ownership_proof.h"
#include "../libspark/spats/spend_transaction.h"
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
        if (!state.RemoveBlock(index))
            throw std::runtime_error("VerifyDB Spark asset rollback failed");
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

bool IsSpatsStarted()
{
    LOCK(cs_main);
    return IsSpatsStarted(chainActive.Height());
}

bool IsSpatsStarted(int height)
{
    return height >= ::Params().GetConsensus().nSpatsStartBlock;
}

unsigned char GetNetworkType() {
    if (::Params().GetConsensus().IsMain())
        return ADDRESS_NETWORK_MAINNET;
    if (::Params().GetConsensus().IsTestnet())
        return ADDRESS_NETWORK_TESTNET;
    if (::Params().GetConsensus().IsDevnet())
        return ADDRESS_NETWORK_DEVNET;
    return ADDRESS_NETWORK_REGTEST;
}

namespace {

size_t GetSpatsMintSerializedMintPayloadByteCount(const CScript& script, const spark::Params* params)
{
    if (!script.IsSpatsMint())
        return 0;
    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    const size_t initial = serialized.size();
    CDataStream stream(serialized, SER_NETWORK, PROTOCOL_VERSION);
    std::vector<CDataStream> serializedCoins = { stream };
    MintTransaction mintTransaction(params);
    try {
        mintTransaction.setMintTransaction(serializedCoins);
    } catch (const std::exception&) {
        return 0;
    }
    return initial - serializedCoins[0].size();
}

} // namespace

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
        if (!script.IsSparkMintType())
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

void ParseSpatsMintTransaction(const CScript& script, MintTransaction& mintTransaction, spark::OwnershipProof& ownershipProof, bool* pfMintOnlyWithoutSparkProof)
{
    if (!script.IsSpatsMint())
        throw std::invalid_argument("Script is not a Spats coin mint");

    const spark::Params* params = spark::Params::get_default();
    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    CDataStream stream(serialized, SER_NETWORK, PROTOCOL_VERSION);
    std::vector<CDataStream> serializedCoins = { stream };

    try {
        mintTransaction.setMintTransaction(serializedCoins);
    } catch (const std::exception &) {
        throw std::invalid_argument("Unable to deserialize Spark mint transaction");
    }

    std::vector<unsigned char> ownership_tail(serializedCoins[0].begin(), serializedCoins[0].end());
    if (ownership_tail.empty()) {
        if (pfMintOnlyWithoutSparkProof)
            *pfMintOnlyWithoutSparkProof = true;
        return;
    }
    if (pfMintOnlyWithoutSparkProof)
        *pfMintOnlyWithoutSparkProof = false;

    const size_t proofsize = spark::OwnershipProof::memoryRequired();
    if (ownership_tail.size() == proofsize) {
        CDataStream proofstream(ownership_tail, SER_NETWORK, PROTOCOL_VERSION);
        proofstream >> ownershipProof;
        return;
    }
    if (ownership_tail.size() == 1 + proofsize && ownership_tail[0] == 0x00) {
        CDataStream proofstream(std::vector<unsigned char>(ownership_tail.begin() + 1, ownership_tail.end()), SER_NETWORK, PROTOCOL_VERSION);
        proofstream >> ownershipProof;
        return;
    }
    throw std::invalid_argument("invalid Spats mint ownership suffix");
}

bool ParseSpatsBurn(const CScript& script, std::pair<Scalar, Scalar>& assetId, CAmount& amount)
{
    if (!script.IsSpatsBurn() || script.size() < 2)
        return false;
    try {
        CDataStream stream(
            std::vector<unsigned char>(script.begin() + 1, script.end()),
            SER_NETWORK, PROTOCOL_VERSION);
        stream >> assetId;
        stream >> amount;
        if (!stream.empty() || amount <= 0 || amount > MAX_ASSET_MONEY)
            return false;
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

void ParseSparkMintCoin(const CScript& script, spark::Coin& txCoin)
{
    if (!script.IsSparkMintType())
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
            const std::vector<unsigned char> extension(
                tx.vExtraPayload.begin() + static_cast<std::ptrdiff_t>(spendSize),
                tx.vExtraPayload.end());
            const uint256& commitment = spendTransaction.getExtensionCommitment();
            auto canonical = [](const CDataStream& encoded, const std::vector<unsigned char>& raw) {
                return encoded.size() == raw.size() &&
                    std::equal(
                        encoded.begin(), encoded.end(), raw.begin(),
                        [](char left, unsigned char right) {
                            return static_cast<unsigned char>(left) == right;
                        });
            };

            bool accepted = false;
            try {
                CDataStream nameStream(extension, SER_NETWORK, PROTOCOL_VERSION);
                CSparkNameTxData nameData;
                nameStream >> nameData;
                if (nameStream.empty()) {
                    CDataStream canonicalName(SER_NETWORK, PROTOCOL_VERSION);
                    canonicalName << nameData;
                    accepted = canonical(canonicalName, extension) &&
                        !commitment.IsNull() &&
                        commitment == CSparkNameManager::GetSparkNameCommitment(nameData);
                }
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception&) {
            }

            if (!accepted) {
                try {
                    CDataStream assetStream(extension, SER_NETWORK, PROTOCOL_VERSION);
                    CSparkAssetTxData assetData;
                    assetStream >> assetData;
                    if (!assetStream.empty()) {
                        throw std::invalid_argument(
                            "Trailing data in Spark V2 extension");
                    }
                    CDataStream canonicalAsset(SER_NETWORK, PROTOCOL_VERSION);
                    canonicalAsset << assetData;
                    if (!canonical(canonicalAsset, extension) ||
                        commitment.IsNull() ||
                        commitment != GetSpatsAssetBindHash(assetData)) {
                        throw std::invalid_argument(
                            "Invalid committed Spark V2 extension");
                    }
                    accepted = true;
                } catch (const std::bad_alloc&) {
                    throw;
                } catch (const std::invalid_argument&) {
                    throw;
                } catch (const std::exception&) {
                    throw std::invalid_argument(
                        "Invalid committed Spark V2 extension");
                }
                if (!accepted) {
                    throw std::invalid_argument(
                        "Invalid committed Spark V2 extension");
                }
            }
        }
    }
    return spendTransaction;
}

spats::SpendTransaction ParseSpatsSpend(const CTransaction &tx)
{
    if (tx.vin.size() != 1 || tx.vin[0].scriptSig.size() < 1) {
        throw CBadTxIn();
    }
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);

    if (tx.vin[0].scriptSig[0] == OP_SPATSSPEND && tx.nVersion >= 3 &&
        (tx.nType == TRANSACTION_SPARK || tx.nType == TRANSACTION_SPARK_V2)) {
        serialized.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    }
    else {
        throw CBadTxIn();
    }
    const spark::Params* params = spark::Params::get_default();
    spats::SpendTransaction spendTransaction(params);
    serialized >> spendTransaction;

    // The asset operation, if any, follows the spend. The spend prefix itself
    // must be the canonical serialization: GroupElement accepts more than one
    // encoding of the same point, and a mutated payload would change the txid
    // without changing the proof.
    const std::size_t spendSize = tx.vExtraPayload.size() - serialized.size();
    CDataStream canonicalSpend(SER_NETWORK, PROTOCOL_VERSION);
    canonicalSpend << spendTransaction;
    if (canonicalSpend.size() != spendSize ||
        !std::equal(
            canonicalSpend.begin(), canonicalSpend.end(),
            tx.vExtraPayload.begin(),
            [](char left, unsigned char right) {
                return static_cast<unsigned char>(left) == right;
            })) {
        throw std::invalid_argument("Non-canonical Spats spend payload");
    }
    return std::move(spendTransaction);
}


Scalar GetSpatsMintM(const CTransaction& tx)
{
    CMutableTransaction txTemp = tx;
    const spark::Params* params = spark::Params::get_default();
    for (auto& txout : txTemp.vout)
        if (txout.scriptPubKey.IsSpatsMint()) {
            const size_t mintBytes = GetSpatsMintSerializedMintPayloadByteCount(txout.scriptPubKey, params);
            const size_t totalPrefix = 1 + mintBytes;
            if (txout.scriptPubKey.size() < totalPrefix)
                continue;
            std::fill(txout.scriptPubKey.begin() + static_cast<std::ptrdiff_t>(totalPrefix), txout.scriptPubKey.end(), 0);
        }
    spark::Hash hash(LABEL_TRANSCRIPT_SPATS_MINT);
    CDataStream serializedTx(SER_NETWORK, PROTOCOL_VERSION);
    serializedTx << txTemp;

    hash.include(serializedTx);
    return hash.finalize_scalar();
}

uint256 GetSpatsMintSpendBindHash(CAmount nValue, const std::vector<unsigned char>& scriptPrefix)
{
    CHashWriter hashStream(SER_GETHASH, PROTOCOL_VERSION);
    hashStream << LABEL_SPATS_MINT_SPEND_BIND;
    hashStream << nValue;
    hashStream << scriptPrefix;
    return hashStream.GetHash();
}

static CAmount CheckedSparkFee(uint64_t fee)
{
    if (fee > static_cast<uint64_t>(MAX_MONEY)) {
        throw std::invalid_argument("Spark spend fee is out of range");
    }
    return static_cast<CAmount>(fee);
}

CAmount GetSparkSpendFee(const CTransaction& tx)
{
    return CheckedSparkFee(ParseSparkSpend(tx).getFee());
}

std::optional<CSparkAssetTxData> GetSparkAssetTxData(const CTransaction& tx)
{
    if (tx.nVersion < 3 ||
        (tx.nType != TRANSACTION_SPARK && tx.nType != TRANSACTION_SPARK_V2) ||
        tx.vExtraPayload.empty())
        return std::nullopt;

    std::size_t offset = 0;
    std::optional<uint256> extensionCommitment;
    if (tx.IsSparkSpend()) {
        if (tx.vin.empty() || tx.vin[0].scriptSig.empty())
            return std::nullopt;
        if (tx.vin[0].scriptSig[0] == OP_SPATSSPEND) {
            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream.write(reinterpret_cast<const char*>(tx.vExtraPayload.data()), tx.vExtraPayload.size());
            spats::SpendTransaction spend(Params::get_default());
            stream >> spend;
            offset = tx.vExtraPayload.size() - stream.size();
        } else if (tx.IsSparkSpendV2()) {
            // ParseSparkSpend has already matched the extension against its commitment.
            const spark::SpendTransaction spend = ParseSparkSpend(tx);
            CDataStream canonicalSpend(SER_NETWORK, PROTOCOL_VERSION);
            canonicalSpend << spend;
            offset = canonicalSpend.size();
            extensionCommitment = spend.getExtensionCommitment();
        } else {
            // Bytes after a V1 Spark spend are a Spark name.
            return std::nullopt;
        }
    }
    if (offset >= tx.vExtraPayload.size())
        return std::nullopt;

    const std::vector<unsigned char> raw(tx.vExtraPayload.begin() + static_cast<std::ptrdiff_t>(offset), tx.vExtraPayload.end());
    CSparkAssetTxData assetData;
    try {
        CDataStream stream(raw, SER_NETWORK, PROTOCOL_VERSION);
        stream >> assetData;
        if (!stream.empty())
            throw std::invalid_argument("Trailing data after Spark asset operation");
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        if (extensionCommitment)
            return std::nullopt; // a Spark name
        throw std::invalid_argument("Invalid Spark asset operation");
    }
    if (extensionCommitment && *extensionCommitment != GetSpatsAssetBindHash(assetData))
        return std::nullopt; // a Spark name that happens to parse
    CDataStream canonical(SER_NETWORK, PROTOCOL_VERSION);
    canonical << assetData;
    if (canonical.size() != raw.size() ||
        !std::equal(canonical.begin(), canonical.end(), raw.begin(),
                    [](char left, unsigned char right) { return static_cast<unsigned char>(left) == right; }))
        throw std::invalid_argument("Non-canonical Spark asset operation");
    return assetData;
}

namespace {

CMutableTransaction UnsignedAssetOwnershipTx(const CTransaction& tx, const CSparkAssetTxData& assetData)
{
    CDataStream signedData(SER_NETWORK, PROTOCOL_VERSION);
    signedData << assetData;
    if (tx.vExtraPayload.size() < signedData.size())
        throw std::invalid_argument("Spark asset operation is not in the payload");

    CSparkAssetTxData unsignedData = assetData;
    unsignedData.setOwnershipProof(std::vector<unsigned char>{});
    CDataStream unsignedStream(SER_NETWORK, PROTOCOL_VERSION);
    unsignedStream << unsignedData;

    CMutableTransaction txTemp = tx;
    txTemp.vExtraPayload.resize(tx.vExtraPayload.size() - signedData.size());
    txTemp.vExtraPayload.insert(txTemp.vExtraPayload.end(), unsignedStream.begin(), unsignedStream.end());
    return txTemp;
}

} // namespace

Scalar GetSpatsAssetOwnershipM(const CTransaction& tx, const CSparkAssetTxData& assetData)
{
    const CTransaction unsignedTx(UnsignedAssetOwnershipTx(tx, assetData));
    spark::Hash hash(LABEL_TRANSCRIPT_SPATS_ASSET_OWNERSHIP);
    CDataStream serializedTx(SER_NETWORK, PROTOCOL_VERSION);
    serializedTx << unsignedTx;
    hash.include(serializedTx);
    return hash.finalize_scalar();
}

uint256 GetSpatsAssetOwnershipHash(const CTransaction& tx, const CSparkAssetTxData& assetData)
{
    const CTransaction unsignedTx(UnsignedAssetOwnershipTx(tx, assetData));
    CHashWriter hashStream(SER_GETHASH, PROTOCOL_VERSION);
    hashStream << LABEL_TRANSCRIPT_SPATS_ASSET_OWNERSHIP;
    hashStream << unsignedTx;
    return hashStream.GetHash();
}

void AddSparkAssetEffects(CSparkAssetPending& pending, const CSparkAssetTxEffects& effects)
{
    if (effects.op)
        pending.symbols.insert(NormalizeSymbol(effects.op->getSymbol()));
    if (effects.opAssetType)
        pending.opAssetTypes.insert(*effects.opAssetType);
    for (const auto& [key, amount] : effects.minted)
        pending.minted[key] += amount;
    for (const auto& [key, amount] : effects.burned)
        pending.burned[key] += amount;
}

void RemoveSparkAssetEffects(CSparkAssetPending& pending, const CSparkAssetTxEffects& effects)
{
    if (effects.op)
        pending.symbols.erase(NormalizeSymbol(effects.op->getSymbol()));
    if (effects.opAssetType)
        pending.opAssetTypes.erase(*effects.opAssetType);
    const auto subtract = [](CAssetState::CirculatingSupplyMap& totals, const CAssetState::CirculatingSupplyMap& amounts) {
        for (const auto& [key, amount] : amounts) {
            auto it = totals.find(key);
            if (it == totals.end())
                continue;
            if (it->second <= amount)
                totals.erase(it);
            else
                it->second -= amount;
        }
    };
    subtract(pending.minted, effects.minted);
    subtract(pending.burned, effects.burned);
}

void AddSparkAssetTxToMempool(CTxMemPool& pool, const uint256& hash, const CSparkAssetTxEffects& effects)
{
    if (effects.IsEmpty())
        return;
    if (!pool.sparkAssetTxs.emplace(hash, effects).second)
        return;
    AddSparkAssetEffects(pool.sparkAssetPending, effects);
}

void RemoveSparkAssetTxFromMempool(CTxMemPool& pool, const uint256& hash)
{
    auto it = pool.sparkAssetTxs.find(hash);
    if (it == pool.sparkAssetTxs.end())
        return;
    RemoveSparkAssetEffects(pool.sparkAssetPending, it->second);
    pool.sparkAssetTxs.erase(it);
}

namespace {

std::optional<spark::Address> DecodeSparkAssetAdmin(const std::string& address)
{
    spark::Address addr(spark::Params::get_default());
    try {
        if (addr.decode(address) == GetNetworkType())
            return addr;
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

bool SignatureCoversAssetPayload(const CTxIn& txin, const CScript& prevScript)
{
    // BIP143 omits vExtraPayload. Only a legacy P2PK/P2PKH signature with
    // SIGHASH_ALL binds the version-3 extra payload (CTransactionSignatureSerializer).
    if (!txin.scriptWitness.IsNull())
        return false;

    txnouttype type;
    std::vector<std::vector<unsigned char>> solutions;
    if (!Solver(prevScript, type, solutions) || (type != TX_PUBKEY && type != TX_PUBKEYHASH))
        return false;

    std::vector<std::vector<unsigned char>> pushes;
    CScript::const_iterator pc = txin.scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    while (pc < txin.scriptSig.end()) {
        if (!txin.scriptSig.GetOp(pc, opcode, data) || opcode > OP_16)
            return false;
        pushes.push_back(std::move(data));
    }
    const size_t expected = (type == TX_PUBKEY) ? 1 : 2;
    if (pushes.size() != expected || pushes.front().empty())
        return false;
    return pushes.front().back() == SIGHASH_ALL;
}

bool SpendsFromTransparentAdmin(const CTransaction& tx, const CCoinsViewCache& inputs, const std::string& admin)
{
    const CBitcoinAddress address(admin);
    if (!address.IsValid() || tx.HasNoRegularInputs())
        return false;
    const CTxDestination adminDest = address.Get();
    for (const CTxIn& txin : tx.vin) {
        const ::Coin& coin = inputs.AccessCoin(txin.prevout);
        if (coin.IsSpent())
            continue;
        CTxDestination dest;
        if (!ExtractDestination(coin.out.scriptPubKey, dest) || dest != adminDest)
            continue;
        if (SignatureCoversAssetPayload(txin, coin.out.scriptPubKey))
            return true;
    }
    return false;
}

bool PaysAssetRegistrationFee(const CTransaction& tx, const Consensus::Params& params, const std::string& symbol)
{
    if (symbol.empty() || symbol.size() >= params.nSpatsRegFee.size() || params.nSpatsRegFee[symbol.size()] < 0)
        return false;
    const CAmount fee = static_cast<CAmount>(params.nSpatsRegFee[symbol.size()]) * COIN;
    const CScript payee = GetScriptForDestination(CBitcoinAddress(params.stage3CommunityFundAddress).Get());
    return std::any_of(tx.vout.begin(), tx.vout.end(), [&](const CTxOut& out) {
        return out.scriptPubKey == payee && out.nValue >= fee;
    });
}

std::uint64_t PendingAmount(const CAssetState::CirculatingSupplyMap& amounts, const CAssetState::CirculatingSupplyKey& key)
{
    const auto it = amounts.find(key);
    return it == amounts.end() ? 0 : it->second;
}

bool HasPendingMint(const CSparkAssetPending& pending, std::uint64_t assetType)
{
    const auto it = pending.minted.lower_bound({assetType, 0});
    return it != pending.minted.end() && it->first.first == assetType;
}

void RemoveSparkAssetConflictsFromMempool(
        CTxMemPool& pool,
        const std::set<std::string>& symbols,
        const std::set<std::uint64_t>& assetTypes)
{
    if (symbols.empty() && assetTypes.empty())
        return;
    LOCK2(cs_main, pool.cs);
    std::vector<CTransaction> conflicting;
    for (const auto& [hash, effects] : pool.sparkAssetTxs) {
        bool touches = (effects.op && symbols.count(NormalizeSymbol(effects.op->getSymbol()))) ||
            (effects.opAssetType && assetTypes.count(*effects.opAssetType));
        for (const auto& minted : effects.minted)
            touches = touches || assetTypes.count(minted.first.first);
        for (const auto& burned : effects.burned)
            touches = touches || assetTypes.count(burned.first.first);
        if (!touches)
            continue;
        auto it = pool.mapTx.find(hash);
        if (it != pool.mapTx.end())
            conflicting.push_back(it->GetTx());
    }
    for (const CTransaction& tx : conflicting) {
        pool.removeRecursive(tx);
        LogPrintf("RemoveSparkAssetConflictsFromMempool: removed %s after a registry change\n", tx.GetHash().ToString());
    }
}

} // namespace

bool CheckSparkAssetTransaction(
        const CTransaction& tx,
        const CCoinsViewCache& inputs,
        CValidationState& state,
        int nHeight,
        bool isVerifyDB,
        bool isMempoolAcceptance,
        const CSparkAssetPending& pending,
        CSparkAssetTxEffects& effects)
{
    effects = CSparkAssetTxEffects();
    const Consensus::Params& params = ::Params().GetConsensus();
    if (nHeight < params.nSpatsStartBlock || tx.IsCoinBase())
        return true;
    // VerifyDB without an isolated context has no registry for this height.
    if (isVerifyDB && !activeVerifyDBContext)
        return true;

    // Failures that depend on the registry or on other pending transactions may clear up later.
    const int contextualDoS = isMempoolAcceptance ? 0 : 100;
    const CAssetState& registry = SparkStateForValidation(isVerifyDB).GetAssetState();
    const bool isSparkSpend = tx.IsSparkSpend();
    const bool isSpatsSpend = !tx.vin.empty() &&
        !tx.vin[0].scriptSig.empty() &&
        tx.vin[0].scriptSig[0] == OP_SPATSSPEND;

    std::optional<CSparkAssetTxData> op;
    try {
        op = GetSparkAssetTxData(tx);
    } catch (const std::bad_alloc&) {
        throw;
    } catch (...) {
        return state.DoS(100, false, REJECT_INVALID, "bad-spats-asset-payload");
    }

    if (op) {
        if (!op->Verify())
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-asset-data");
        const std::string symbol = NormalizeSymbol(op->getSymbol());
        if (pending.symbols.count(symbol))
            return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-asset-op-conflict");

        std::string admin;
        if (op->isRegister()) {
            if (registry.IsSymbolTaken(symbol))
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-asset-symbol-taken");
            if (!PaysAssetRegistrationFee(tx, params, op->getSymbol()))
                return state.DoS(100, false, REJECT_INVALID, "bad-spats-asset-fee");
            // The address being assigned must sign this registration.
            admin = op->getAdminPublicAddress();
        } else {
            const auto assetType = registry.GetAssetTypeBySymbol(symbol);
            const auto entry = assetType ? registry.Get(*assetType) : std::nullopt;
            if (!entry)
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-asset-unknown");
            if (entry->adminPublicAddress != op->getAdminPublicAddress())
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-asset-not-admin");
            if (HasPendingMint(pending, *assetType))
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-asset-op-conflict");
            if (op->isTransfer() && !IsValidAssetAdminAddress(op->getTransferAddress()))
                return state.DoS(100, false, REJECT_INVALID, "bad-spats-asset-transfer-address");
            if (op->isTransfer() &&
                !VerifySpatsAssetReceiverProof(
                    *assetType,
                    entry->adminPublicAddress,
                    op->getTransferAddress(),
                    op->getRecieverOwnershipProof()))
                return state.DoS(100, false, REJECT_INVALID, "spats-asset-receiver-ownership-invalid");
            admin = entry->adminPublicAddress;
            effects.opAssetType = *assetType;
        }

        if (!isSparkSpend)
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-asset-admin-tx");
        Scalar m;
        uint256 transparentHash;
        try {
            m = GetSpatsAssetOwnershipM(tx, *op);
            transparentHash = GetSpatsAssetOwnershipHash(tx, *op);
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception&) {
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-asset-payload");
        }
        if (!VerifySpatsAssetAdminProof(admin, m, transparentHash, op->getOwnershipProof()))
            return state.DoS(100, false, REJECT_INVALID, "spats-asset-ownership-invalid");
        effects.op = op;
    }

    for (const CTxOut& txout : tx.vout) {
        if (!txout.scriptPubKey.IsSpatsMint())
            continue;
        if (op)
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-op-and-mint");

        MintTransaction mintTransaction(Params::get_default());
        OwnershipProof proof;
        bool noProof = false;
        try {
            ParseSpatsMintTransaction(txout.scriptPubKey, mintTransaction, proof, &noProof);
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception&) {
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-mint");
        }
        std::vector<Coin> coins;
        mintTransaction.getCoins(coins);
        if (coins.size() != 1 || coins[0].v == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-mint");

        const auto assetType = GetSpatsScalarAsUint64(coins[0].a);
        const auto identifier = GetSpatsScalarAsUint64(coins[0].iota);
        const auto entry = assetType ? registry.Get(*assetType) : std::nullopt;
        if (!entry || !identifier)
            return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-mint-unknown-asset");
        if (pending.opAssetTypes.count(*assetType) || pending.symbols.count(NormalizeSymbol(entry->symbol)))
            return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-mint-op-conflict");

        const CAssetState::CirculatingSupplyKey key{*assetType, *identifier};
        const std::uint64_t amount = coins[0].v;
        const std::uint64_t current = registry.GetCirculatingSupply(*assetType, *identifier);
        const std::uint64_t pendingMinted = PendingAmount(pending.minted, key) + PendingAmount(effects.minted, key);
        if (entry->assetKind == static_cast<uint8_t>(AssetKind::NonFungible)) {
            if (amount != 1)
                return state.DoS(100, false, REJECT_INVALID, "spats-nft-value");
            if (*identifier != entry->identifier)
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-mint-wrong-identifier");
            if (current != 0 || pendingMinted != 0)
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-nft-already-minted");
        } else {
            if (*identifier != 0)
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-mint-wrong-identifier");
            const std::uint64_t cap = entry->maxSupply != 0
                ? entry->maxSupply
                : static_cast<std::uint64_t>(MAX_ASSET_MONEY);
            if (amount > cap || current > cap - amount || pendingMinted > cap - amount - current)
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-mint-exceeds-max-supply");
        }

        if (const auto sparkAdmin = DecodeSparkAssetAdmin(entry->adminPublicAddress)) {
            if (!isSparkSpend || noProof)
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-mint-ownership-missing");
            if (!sparkAdmin->verify_own(GetSpatsMintM(tx), proof))
                return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-mint-ownership-invalid");
        } else if (isSparkSpend || !noProof ||
                   !SpendsFromTransparentAdmin(tx, inputs, entry->adminPublicAddress)) {
            return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-mint-admin-input-missing");
        }
        effects.minted[key] += amount;
    }

    bool sawBurn = false;
    for (const CTxOut& txout : tx.vout) {
        if (!txout.scriptPubKey.IsSpatsBurn())
            continue;
        if (sawBurn)
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-burn");
        sawBurn = true;
        if (!isSpatsSpend)
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-burn");
        if (txout.nValue != 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-burn-nvalue");
        std::pair<Scalar, Scalar> assetId;
        CAmount burnAmount = 0;
        if (!ParseSpatsBurn(txout.scriptPubKey, assetId, burnAmount))
            return state.DoS(100, false, REJECT_INVALID, "bad-spats-burn");
        const auto assetType = GetSpatsScalarAsUint64(assetId.first);
        const auto entry = assetType ? registry.Get(*assetType) : std::nullopt;
        if (!entry || entry->assetKind != static_cast<uint8_t>(AssetKind::Fungible) ||
            assetId.first.isZero() || !assetId.second.isZero())
            return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-burn-unknown-asset");
        const CAssetState::CirculatingSupplyKey key{*assetType, 0};
        const std::uint64_t amount = static_cast<std::uint64_t>(burnAmount);
        const std::uint64_t current = registry.GetCirculatingSupply(*assetType, 0);
        const std::uint64_t pendingBurned = PendingAmount(pending.burned, key) + PendingAmount(effects.burned, key);
        if (amount > current || pendingBurned > current - amount)
            return state.DoS(contextualDoS, false, REJECT_INVALID, "spats-burn-exceeds-supply");
        effects.burned[key] += amount;
    }

    return true;
}


std::vector<GroupElement> GetSparkUsedTags(const CTransaction &tx)
{
    try {
        if (!tx.vin.empty() && !tx.vin[0].scriptSig.empty() &&
            tx.vin[0].scriptSig[0] == OP_SPATSSPEND) {
            return ParseSpatsSpend(tx).getUsedLTags();
        }
        return ParseSparkSpend(tx).getUsedLTags();
    } catch (const std::bad_alloc &) {
        throw;
    } catch (const std::exception &) {
        return std::vector<GroupElement>();
    }
}

CAmount GetSparkFee(const CTransaction &tx)
{
    if (tx.vin[0].scriptSig[0] == OP_SPARKSPEND) {
        return CheckedSparkFee(ParseSparkSpend(tx).getFee());
    } else if (tx.vin[0].scriptSig[0] == OP_SPATSSPEND) {
        return CheckedSparkFee(ParseSpatsSpend(tx).getFee());
    }
    return CAmount();
}

std::map<uint64_t, uint256> getBlockHashes(const CTransaction &tx)
{
    const spark::Params* params = spark::Params::get_default();

    if (tx.vin[0].scriptSig[0] == OP_SPARKSPEND) {
        spark::SpendTransaction spendTransaction(params);
        spendTransaction = ParseSparkSpend(tx);
        return  spendTransaction.getBlockHashes();
    }
    else if (tx.vin[0].scriptSig[0] == OP_SPATSSPEND) {
        spats::SpendTransaction spendTransaction(params);
        spendTransaction = ParseSpatsSpend(tx);
        return  spendTransaction.getBlockHashes();
    }
    return std::map<uint64_t, uint256>();
}

std::vector<spark::Coin> GetSparkMintCoins(const CTransaction &tx)
{
    std::vector<spark::Coin> result;

    if (tx.IsSparkTransaction()) {
        std::vector<unsigned char> serial_context = getSerialContext(tx);
        for (const auto& vout : tx.vout) {
            const auto& script = vout.scriptPubKey;
            if (script.IsSparkMint() || script.IsSpatsMint() ||
                    (script.IsSparkSMint() && tx.IsSparkSpend())) {
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

    for (const CTxOut &txout : tx.vout) {
        const auto& script = txout.scriptPubKey;
        if (script.IsSparkSMint() || script.IsSpatsMint() || script.IsSpatsBurn())
            continue;
        result += txout.nValue;
    }
    return result;
}

bool IsSparkSpendFormatAllowed(const CTransaction& tx, int height)
{
    if (!tx.IsSparkSpend()) {
        return true;
    }

    const auto& consensus = ::Params().GetConsensus();
    if (!tx.vin.empty() &&
        !tx.vin[0].scriptSig.empty() &&
        tx.vin[0].scriptSig[0] == OP_SPATSSPEND &&
        height < consensus.nSpatsStartBlock) {
        return false;
    }
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

        if (fJustCheck) {
            if (isVerifyDB && activeVerifyDBContext) {
                activeVerifyDBContext->AddBlock(pindexNew);
            }
            return true;
        }

        // Complete per-block name data distinguishes a replayed registration
        // from a renewal of the manager's current record.
        bool fSparkNamesAlreadyIndexed =
            !pblock->sparkTxInfo->sparkNames.empty() &&
            pindexNew->hasPrivacyData();
        if (fSparkNamesAlreadyIndexed) {
            const auto& pd = pindexNew->privacyData();
            for (const auto& sparkName : pblock->sparkTxInfo->sparkNames) {
                const uint8_t opType = sparkName.second.nVersion >= 2 ?
                    sparkName.second.operationType :
                    static_cast<uint8_t>(CSparkNameTxData::opRegister);
                const bool indexed =
                    opType == CSparkNameTxData::opUnregister ?
                        pd.removedSparkNames.find(sparkName.first) !=
                            pd.removedSparkNames.end() :
                        pd.addedSparkNames.find(sparkName.first) !=
                            pd.addedSparkNames.end();
                if (!indexed) {
                    fSparkNamesAlreadyIndexed = false;
                    break;
                }
            }
        }

        // Reconnecting an existing index entry rebuilds transaction-derived
        // Spark metadata. Keep active sporks and removed Spark names: the
        // latter also contains expiry undo data that cannot be reconstructed
        // when replaying against an already-applied name state.
        if (pindexNew->hasPrivacyData()) {
            auto& pd = pindexNew->ensurePrivacyData();
            pd.sparkMintedCoins.clear();
            pd.spentLTags.clear();
            pd.sparkSetHash.clear();
            pd.sparkTxHashContext.clear();
            pd.ltagTxhash.clear();
            pd.addedSparkNames.clear();
            pd.sparkAssetOps.clear();
            pd.sparkAssetMinted.clear();
            pd.sparkAssetBurned.clear();
        }

        // Allocate privacy data only if this block has something to store.
        BOOST_FOREACH (auto& lTag, pblock->sparkTxInfo->spentLTags) {
            pindexNew->ensurePrivacyData().spentLTags.insert(lTag);
            sparkState.AddSpend(lTag.first, lTag.second);
        }
        if (GetBoolArg("-mobile", false)) {
            BOOST_FOREACH (auto& lTag, pblock->sparkTxInfo->ltagTxhash) {
                pindexNew->ensurePrivacyData().ltagTxhash.insert(lTag);
                sparkState.AddLTagTxHash(lTag.first, lTag.second);
            }
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
            if (prev_hash.empty() && latestCoinId > 1)
                prev_hash = GetAnonymitySetHash(pindexNew->pprev, latestCoinId - 1, true, includeFirstBlock);

            if (prev_hash.size() == CSHA256::OUTPUT_SIZE)
                hash.Write(prev_hash.data(), prev_hash.size());
            else if (!prev_hash.empty())
                LogPrintf("ConnectBlockSpark: ignoring malformed previous set hash of size %u\n", static_cast<unsigned int>(prev_hash.size()));

            const auto& mintedCoins =
                pindexNew->privacyData().sparkMintedCoins;
            const auto mintedCoinsIt = mintedCoins.find(latestCoinId);
            if (mintedCoinsIt != mintedCoins.end()) {
                for (const auto &coin : mintedCoinsIt->second) {
                    CDataStream serializedCoin(SER_NETWORK, 0);
                    serializedCoin << coin;
                    std::vector<unsigned char> data(serializedCoin.begin(), serializedCoin.end());
                    hash.Write(data.data(), data.size());
                }
            } else
                LogPrintf("ConnectBlockSpark: missing minted coins for group %d\n", latestCoinId);
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
                            // On replay, the manager can already contain post-block
                            // state. Retained undo is the authoritative prior expiry.
                            const auto& removedNames =
                                pindexNew->privacyData().removedSparkNames;
                            const auto removedName =
                                removedNames.find(sparkName.first);
                            int existingExpirationHeight = pindexNew->nHeight;
                            if (removedName != removedNames.end())
                                existingExpirationHeight =
                                    removedName->second.sparkNameValidityHeight;
                            else if (!fSparkNamesAlreadyIndexed)
                                existingExpirationHeight =
                                    sparkNameManager->GetSparkNameBlockHeight(sparkName.first);
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
                            {
                                auto& removedNames =
                                    pindexNew->ensurePrivacyData().removedSparkNames;
                                if (removedNames.find(sparkName.first) ==
                                    removedNames.end()) {
                                    removedNames.emplace(
                                        sparkName.first,
                                        CSparkNameBlockIndexData(
                                            sparkName.second.name,
                                            sparkName.second.oldSparkAddress,
                                            sparkNameManager->GetSparkNameBlockHeight(sparkName.first),
                                            sparkNameManager->GetSparkNameAdditionalData(sparkName.first)));
                                }
                            }

                            pindexNew->ensurePrivacyData().addedSparkNames[sparkName.first] =
                                CSparkNameBlockIndexData(sparkName.second.name,
                                    sparkName.second.sparkAddress,
                                    pindexNew->nHeight + validityBlocks,
                                    sparkName.second.additionalInfo);

                            break;

                        case CSparkNameTxData::opUnregister:
                            {
                                auto& removedNames =
                                    pindexNew->ensurePrivacyData().removedSparkNames;
                                if (removedNames.find(sparkName.first) ==
                                    removedNames.end()) {
                                    removedNames.emplace(
                                        sparkName.first,
                                        CSparkNameBlockIndexData(
                                            sparkName.second.name,
                                            sparkName.second.sparkAddress,
                                            sparkNameManager->GetSparkNameBlockHeight(sparkName.first),
                                            sparkNameManager->GetSparkNameAdditionalData(sparkName.first)));
                                }
                            }
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
            fBackupRewrittenSparkNames = !fSparkNamesAlreadyIndexed;
        }

        // generate hash if we need it
        if (updateHash) {
            unsigned char hash_result[CSHA256::OUTPUT_SIZE];
            hash.Finalize(hash_result);
            auto &out_hash = pindexNew->ensurePrivacyData().sparkSetHash[sparkState.GetLatestCoinID()];
            out_hash.clear();
            out_hash.insert(out_hash.begin(), std::begin(hash_result), std::end(hash_result));
        }

        const CSparkTxInfo& info = *pblock->sparkTxInfo;
        if (!info.assetOps.empty() || !info.assetPending.minted.empty() || !info.assetPending.burned.empty()) {
            if (!sparkState.ConnectAssetBlock(pindexNew, info))
                return state.DoS(100, error("ConnectBlockSpark: failed to apply spark asset registry"));

            // Pending asset transactions were checked against the registry before this block.
            std::set<std::string> symbols;
            std::set<std::uint64_t> assetTypes;
            for (const auto& op : pindexNew->privacyData().sparkAssetOps) {
                symbols.insert(NormalizeSymbol(op.after.symbol));
                assetTypes.insert(op.assetType);
            }
            for (const auto& minted : info.assetPending.minted)
                assetTypes.insert(minted.first.first);
            for (const auto& burned : info.assetPending.burned)
                assetTypes.insert(burned.first.first);
            RemoveSparkAssetConflictsFromMempool(mempool, symbols, assetTypes);
            RemoveSparkAssetConflictsFromMempool(txpools.getStemTxPool(), symbols, assetTypes);
        }
    }
    else if (!fJustCheck) {
        if (!sparkState.AddBlock(pindexNew))
            return state.DoS(100, error("ConnectBlockSpark: failed to apply indexed spark asset state"));
    }

    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();

    auto removedNames = sparkNameManager->RemoveSparkNamesLosingValidity(pindexNew->nHeight);
    for (const auto &name: removedNames)
        pindexNew->ensurePrivacyData().removedSparkNames.emplace(name.first, name.second);
    
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
                    std::map<uint64_t, uint256> coinGroupIdAndBlockHash;
                    try {
                        coinGroupIdAndBlockHash = getBlockHashes(tx);
                    }
                    catch (const std::exception &) {
                        txn_to_remove.push_back(tx);
                        break;
                    }


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

bool DisconnectTipSpark(CBlock& block, CBlockIndex *pindexDelete) {
    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
    sparkNameManager->RemoveBlock(pindexDelete);

    if (!sparkState.RemoveBlock(pindexDelete))
        return error("DisconnectTipSpark: spark asset supply rollback failed");

    {
        std::set<std::string> symbols;
        std::set<std::uint64_t> assetTypes;
        const auto& pd = pindexDelete->privacyData();
        for (const auto& op : pd.sparkAssetOps) {
            symbols.insert(NormalizeSymbol(op.after.symbol));
            assetTypes.insert(op.assetType);
        }
        for (const auto& minted : pd.sparkAssetMinted)
            assetTypes.insert(minted.first.first);
        for (const auto& burned : pd.sparkAssetBurned)
            assetTypes.insert(burned.first.first);
        RemoveSparkAssetConflictsFromMempool(mempool, symbols, assetTypes);
        RemoveSparkAssetConflictsFromMempool(txpools.getStemTxPool(), symbols, assetTypes);
    }

    // Spark verification depends on active-chain cover-set data. Refresh all
    // cached results after a disconnect so they use the current chain context.
    ClearSparkSpendProofCache();

    // Also remove from mempool spends that reference given block hash.
    RemoveSpendReferencingBlock(mempool, pindexDelete);
    RemoveSpendReferencingBlock(txpools.getStemTxPool(), pindexDelete);
    return true;
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

        // Spark mints are FIRO. An asset id here would enter the cover set
        // without CheckSparkAssetTransaction's registry, admin, and supply checks.
        if (!coin.a.isZero() || !coin.iota.isZero())
            return state.DoS(100,
                             false,
                             PUBCOIN_NOT_VALIDATE,
                             "CheckSparkMintTransaction : spark mint with asset type");

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

bool CheckSpatsMintTransaction(
        const CTransaction &tx,
        CTxOut& txOut,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo) {

    LogPrintf("CheckSpatsMintTransaction txHash = %s\n", hashTx.GetHex());
    const spark::Params* params = spark::Params::get_default();

    MintTransaction mintTransaction(params);
    spark::OwnershipProof ownershipProof;
    try {
        ParseSpatsMintTransaction(txOut.scriptPubKey, mintTransaction, ownershipProof);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CTransaction::CheckTransaction() : SpatsMint parsing failure.");
    }

    //checking whether MintTransaction is valid
    if (!mintTransaction.verify()) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSpatsMintTransaction : mintTransaction verification failed");
    }
    std::vector<Coin> coins;
    mintTransaction.getCoins(coins);

    if (coins.size() != 1)
        return state.DoS(100,
                     false,
                     PUBCOIN_NOT_VALIDATE,
                     "CheckSpatsMintTransaction : More than one spats mint");

    // Admin authorization, identifier and supply are checked against the registry in CheckSparkAssetTransaction.
    // Asset amount lives in the minted coin. nValue is not FIRO and must be zero
    // so a transparent mint cannot lock a matching transparent balance.
    auto& coin = coins[0];
    if (txOut.nValue != 0)
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSpatsMintTransaction : nonzero spats mint output");

    if (coin.a == ZERO)
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSpatsMintTransaction : Invalid asset type");

    // A nonzero identifier is an NFT. The Spats mint rule requires its value to be 1
    // so the token cannot be split by a later spend.
    if (!coin.iota.isZero() && coin.v != 1)
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSpatsMintTransaction : nft value must be 1");

    if (sparkTxInfo != nullptr && !sparkTxInfo->fInfoIsComplete) {
        // Update coin list in the info
        sparkTxInfo->mints.push_back(coin);
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

    std::unique_ptr<spark::BaseSpendTransaction> spend;
    const bool isSpatsSpend = !tx.vin.empty() &&
        !tx.vin[0].scriptSig.empty() &&
        tx.vin[0].scriptSig[0] == OP_SPATSSPEND;
    if (isSpatsSpend && height < params.nSpatsStartBlock) {
        return state.DoS(isMempoolAcceptance ? 0 : 100,
                         false,
                         isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                         "CheckSparkSpendTransaction: spats spend before spats activation");
    }

    try {
        if (isSpatsSpend)
            spend = std::make_unique<spats::SpendTransaction>(ParseSpatsSpend(tx));
        else
            spend = std::make_unique<spark::SpendTransaction>(ParseSparkSpend(tx));
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
                return output.scriptPubKey.IsSparkSMint() ||
                    output.scriptPubKey.IsSpatsMint() ||
                    output.scriptPubKey.IsSpatsBurn();
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
    if (isSpatsSpend &&
        height >= params.nSparkChaumV2StartBlock &&
        !isChaumV2) {
        return state.DoS(isMempoolAcceptance ? 0 : 100,
                         false,
                         isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                         "CheckSparkSpendTransaction: spats spend requires CHAUM_V2");
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
    uint64_t burn = 0;
    std::optional<std::pair<Scalar, Scalar>> burn_asset_id;
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
        } else if (script.IsSpatsMint()) {
            continue;
        } else if (script.IsSpatsBurn()) {
            if (burn_asset_id) {
                return state.DoS(100, false, REJECT_INVALID,
                    "CheckSparkSpendTransaction: multiple spats burn outputs");
            }
            if (txout.nValue != 0) {
                return state.DoS(100, false, REJECT_INVALID, "bad-spats-burn-nvalue");
            }
            std::pair<Scalar, Scalar> asset_id_scalars;
            CAmount burnAmount = 0;
            try {
                if (!ParseSpatsBurn(script, asset_id_scalars, burnAmount)) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "CheckSparkSpendTransaction: invalid spats burn output");
                }
            } catch (const std::bad_alloc&) {
                return state.Error(
                    "CheckSparkSpendTransaction: memory allocation failed while parsing spats burn");
            }
            if (!asset_id_scalars.second.isZero()) {
                return state.DoS(100, false, REJECT_INVALID,
                    "CheckSparkSpendTransaction: spats burn identifier is not zero");
            }
            burn += static_cast<uint64_t>(burnAmount);
            burn_asset_id = asset_id_scalars;
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

    if (burn > 0) {
        if (height < params.nSpatsStartBlock) {
            return state.DoS(isMempoolAcceptance ? 0 : 100,
                             false,
                             isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                             "CheckSparkSpendTransaction: spats burn before spats activation");
        }
        if (!isSpatsSpend) {
            return state.DoS(100, false, REJECT_INVALID,
                "CheckSparkSpendTransaction: spats burn requires a spats spend");
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
    const bool fCanBatch = !isVerifyDB && !isCheckWallet && sparkTxInfo && !sparkTxInfo->fInfoIsComplete;

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
    spend->setBurn(burn);
    if (spend->isSpats() && burn > 0) {
        if (!burn_asset_id) {
            return state.DoS(100, false, REJECT_INVALID,
                "CheckSparkSpendTransaction: spats burn missing asset id");
        }
        auto* spats_spend = static_cast<spats::SpendTransaction*>(spend.get());
        spats_spend->setBurnAssetId(burn_asset_id->first, burn_asset_id->second);
    }

    // The mint coin is not part of the metadata hash. Bind its on-chain prefix
    // into the spend proof so a replaced SPATSMINT output fails verification.
    {
        int mintCount = 0;
        bool mintWellFormed = true;
        uint256 mintBind;
        for (const CTxOut& txout : tx.vout) {
            if (!txout.scriptPubKey.IsSpatsMint())
                continue;
            ++mintCount;
            if (mintCount > 1) {
                mintWellFormed = false;
                break;
            }
            const size_t mintBytes = GetSpatsMintSerializedMintPayloadByteCount(
                txout.scriptPubKey, spark::Params::get_default());
            if (mintBytes == 0 || txout.scriptPubKey.size() < 1 + mintBytes) {
                mintWellFormed = false;
                break;
            }
            const std::vector<unsigned char> prefix(
                txout.scriptPubKey.begin(),
                txout.scriptPubKey.begin() + static_cast<std::ptrdiff_t>(1 + mintBytes));
            mintBind = GetSpatsMintSpendBindHash(txout.nValue, prefix);
        }
        if (mintCount > 0 && height < params.nSpatsStartBlock) {
            return state.DoS(isMempoolAcceptance ? 0 : 100,
                             false,
                             isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                             "CheckSparkSpendTransaction: spats mint before spats activation");
        }
        if (mintCount > 0 && (!spend->isSpats() || !mintWellFormed)) {
            return state.DoS(100, false, REJECT_INVALID,
                "CheckSparkSpendTransaction: spats mint is not bound to the spend");
        }

        // A Spark V2 spend commits to a trailing asset operation through its extension;
        // a SPATS spend commits to it through extraDataHash, like a mint.
        std::optional<CSparkAssetTxData> assetData;
        if (spend->isSpats() && height >= params.nSpatsStartBlock) {
            try {
                assetData = GetSparkAssetTxData(tx);
            } catch (const std::bad_alloc&) {
                return state.Error(
                    "CheckSparkSpendTransaction: memory allocation failed while parsing asset data");
            } catch (const std::exception&) {
                return state.DoS(100, false, REJECT_INVALID,
                    "CheckSparkSpendTransaction: invalid spark asset operation");
            }
        }
        if (assetData && mintCount > 0) {
            return state.DoS(100, false, REJECT_INVALID,
                "CheckSparkSpendTransaction: spats mint and asset operation in one spend");
        }
        if (mintCount == 1) {
            static_cast<spats::SpendTransaction*>(spend.get())->setExtraDataHash(mintBind);
        } else if (assetData) {
            static_cast<spats::SpendTransaction*>(spend.get())->setExtraDataHash(GetSpatsAssetBindHash(*assetData));
        }
    }

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
    
    // Recent blocks retain the mempool cache fast path. Historical batches
    // still collect every proof, and VerifyDB always re-verifies its own view.
    // The txid cache stores Spark spends only.
    bool haveCachedSuccess = false;
    if (!isVerifyDB && !spend->isSpats() && (!fCanBatch || !batchProofContainer->is_deferred())) {
        LOCK(cs_checkedSparkSpendTransactions);
        haveCachedSuccess = gCheckedSparkSpendTransactions.exists(hashTx);
    }
    bool fAddedToBatch = false;
    if (!haveCachedSuccess && fCanBatch) {
        if (spend->isSpats()) {
            fAddedToBatch = batchProofContainer->add(
                *static_cast<spats::SpendTransaction*>(spend.get()), hashTx);
        } else if (isChaumV2 || requireChaumV1SingleInput) {
            fAddedToBatch = batchProofContainer->add(
                *static_cast<spark::SpendTransaction*>(spend.get()), hashTx);
        } else {
            fAddedToBatch = batchProofContainer->addHistorical(
                *static_cast<spark::SpendTransaction*>(spend.get()), hashTx);
        }
    }
    if (haveCachedSuccess || fAddedToBatch) {
        passVerify = true;
    } else {
        try {
            if (spend->isSpats()) {
                std::unordered_map<uint64_t, std::vector<Coin>> cover_sets;
                for (uint64_t id : ids) {
                    cover_sets.emplace(id, coverSetProvider(id));
                }
                passVerify = spats::SpendTransaction::verify(
                    *static_cast<spats::SpendTransaction*>(spend.get()),
                    cover_sets);
            } else if (isMempoolAcceptance) {
                passVerify = spark::SpendTransaction::verify(
                    spark::Params::get_default(),
                    {*static_cast<spark::SpendTransaction*>(spend.get())},
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
                        {*static_cast<spark::SpendTransaction*>(spend.get())},
                        coverSetProvider)
                    : spark::SpendTransaction::verifyHistorical(
                        spark::Params::get_default(),
                        {*static_cast<spark::SpendTransaction*>(spend.get())},
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

    // Check Spats Mint Transaction. VerifyDB must parse the mint too, so the
    // coin is on sparkTxInfo->mints for the duplicate check and the mint proof
    // is re-checked. The anonymity set itself is restored from the block index.
    if (allowSpark && tx.IsSpatsMint()) {
        std::vector<CTxOut> txOuts;
        for (const CTxOut &txout : tx.vout) {
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsSpatsMint()) {
                txOuts.push_back(txout);
            }
        }

        // Registry and supply checks do not run before this height. Parsing the
        // mint here would still add the coin to the cover set.
        if (nRealHeight < consensus.nSpatsStartBlock) {
            const bool isMempoolAcceptance = sparkTxInfo == nullptr && nHeight == INT_MAX;
            return state.DoS(isMempoolAcceptance ? 0 : 100,
                             false,
                             isMempoolAcceptance ? REJECT_NONSTANDARD : REJECT_INVALID,
                             "CheckSparkTransaction: spats mint before spats activation");
        }

        if (txOuts.size() > 1) {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "bad-txns-mint-invalid");
        }

        if (!txOuts.empty()) {
            try {
                if (!CheckSpatsMintTransaction(tx, txOuts[0], state, hashTx, fStatefulSigmaCheck, sparkTxInfo)) {
                    LogPrintf("CheckSparkTransaction::Spats Mint verification failed.\n");
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

bool GetOutPointFromBlock(COutPoint& outPoint, const spark::Coin& coin, const CBlock &block, CTransactionRef* txOut) {
    if (txOut)
        txOut->reset();

    spark::Coin txCoin(coin.params);
    // cycle transaction hashes, looking for this coin
    for (CTransactionRef tx : block.vtx){
        uint32_t nIndex = 0;
        for (const CTxOut &txout : tx->vout) {
            if (txout.scriptPubKey.IsSparkMint() || txout.scriptPubKey.IsSpatsMint() ||
                    (txout.scriptPubKey.IsSparkSMint() && tx->IsSparkSpend())) {
                try {
                    ParseSparkMintCoin(txout.scriptPubKey, txCoin);
                }
                catch (const std::exception &) {
                    continue;
                }
                if (coin == txCoin) {
                    outPoint = COutPoint(tx->GetHash(), nIndex);
                    if (txOut)
                        *txOut = tx;
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
            if (!tx.vin.empty() && !tx.vin[0].scriptSig.empty() &&
                tx.vin[0].scriptSig[0] == OP_SPATSSPEND) {
                serialContextStream << ParseSpatsSpend(tx).getUsedLTags();
            } else {
                spark::SpendTransaction spend = ParseSparkSpend(tx);
                serialContextStream << spend.getUsedLTags();
            }
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
    asset_state_ = other.asset_state_;
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
    ltagTxhash.clear();
    extendedMintMetaInfo.clear();
    mintMetaInfo.clear();
    spendMetaInfo.clear();
    asset_state_.Clear();
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
            CTransactionRef tx;
            if (!GetOutPointFromBlock(outPoint, mint, *pblock, &tx)) {
                LogPrintf("AddMintsToStateAndBlockIndex: unable to locate Spark mint transaction in block %s\n", pblock->GetHash().ToString());
                continue;
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

bool CSparkState::AddBlock(CBlockIndex *index) {
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

    return ApplyAssetBlock(pd);
}

bool CSparkState::ConnectAssetBlock(CBlockIndex *index, const CSparkTxInfo& info)
{
    std::vector<CSparkAssetIndexOp> ops;
    std::uint64_t nextAssetType = asset_state_.GetNextAssetTypeCounter();
    for (const auto& [txid, data] : info.assetOps) {
        CSparkAssetIndexOp op;
        if (data.isRegister()) {
            op.fRegister = true;
            op.assetType = nextAssetType++;
            op.after = CSparkAssetDBEntry(data);
            op.after.registeringTxid = txid;
            op.after.nHeight = index->nHeight;
        } else {
            const auto assetType = asset_state_.GetAssetTypeBySymbol(data.getSymbol());
            const auto entry = assetType ? asset_state_.Get(*assetType) : std::nullopt;
            if (!entry)
                return error("ConnectAssetBlock: asset operation for unknown symbol %s", data.getSymbol());
            op.assetType = *assetType;
            op.before = *entry;
            op.after = *entry;
            if (data.isNameModify())
                op.after.name = data.getName();
            else if (data.isDescriptionModify())
                op.after.description = data.getDescription();
            else if (data.isMetadataModify())
                op.after.metadata = data.getMetadata();
            else if (data.isTransfer())
                op.after.adminPublicAddress = data.getTransferAddress();
            else
                return error("ConnectAssetBlock: unknown asset operation for symbol %s", data.getSymbol());
        }
        ops.push_back(std::move(op));
    }

    CBlockIndexPrivacyData staged;
    staged.sparkAssetOps = std::move(ops);
    staged.sparkAssetMinted = info.assetPending.minted;
    staged.sparkAssetBurned = info.assetPending.burned;
    if (!ApplyAssetBlock(staged))
        return error("ConnectAssetBlock: spark asset supply change rejected");

    auto& pd = index->ensurePrivacyData();
    pd.sparkAssetOps = std::move(staged.sparkAssetOps);
    pd.sparkAssetMinted = std::move(staged.sparkAssetMinted);
    pd.sparkAssetBurned = std::move(staged.sparkAssetBurned);
    return true;
}

bool CSparkState::ApplyAssetBlock(const CBlockIndexPrivacyData& pd)
{
    CAssetState next = asset_state_;
    for (const auto& op : pd.sparkAssetOps)
        next.SetEntry(op.assetType, op.after);
    for (const auto& [key, amount] : pd.sparkAssetMinted) {
        if (!next.AddCirculatingSupply(key.first, key.second, amount))
            return false;
    }
    for (const auto& [key, amount] : pd.sparkAssetBurned) {
        if (!next.SubCirculatingSupply(key.first, key.second, amount))
            return false;
    }
    asset_state_ = std::move(next);
    return true;
}

bool CSparkState::UndoAssetBlock(const CBlockIndexPrivacyData& pd)
{
    CAssetState next = asset_state_;
    for (const auto& [key, amount] : pd.sparkAssetBurned) {
        if (!next.AddCirculatingSupply(key.first, key.second, amount))
            return false;
    }
    for (const auto& [key, amount] : pd.sparkAssetMinted) {
        if (!next.SubCirculatingSupply(key.first, key.second, amount))
            return false;
    }
    for (auto op = pd.sparkAssetOps.rbegin(); op != pd.sparkAssetOps.rend(); ++op) {
        if (op->fRegister)
            next.UndoRegister(op->assetType);
        else
            next.SetEntry(op->assetType, op->before);
    }
    asset_state_ = std::move(next);
    return true;
}

bool CSparkState::RemoveBlock(CBlockIndex *index) {
    if (!UndoAssetBlock(index->privacyData()))
        return false;
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

            while (true) {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
                const auto& mintedCoins =
                    coinGroup.lastBlock->privacyData().sparkMintedCoins;
                if (mintedCoins.find(coins.first) != mintedCoins.end())
                    break;
            }
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

    return true;
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
    if (!coinGroups.contains(coinGroupID)) {
        throw std::runtime_error("There is no anonymity set with this id: " + std::to_string(coinGroupID));
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
        // ignore block higher than max height
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

            size_t inBlock = 0;
            const auto& mintedCoins = block->privacyData().sparkMintedCoins;
            auto it = mintedCoins.find(groupId);
            if (it != mintedCoins.end() && (inBlock = it->second.size())) {

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
