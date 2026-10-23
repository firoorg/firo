// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _MAIN_SPARK_STATE_H_
#define _MAIN_SPARK_STATE_H_

#include "libspark/coin.h"
#include "chain.h"
#include "../wallet/wallet.h"
#include "../libspark/mint_transaction.h"
#include "../libspark/spend_transaction.h"
#include "../libspark/spats/spend_transaction.h"
#include "assetstate.h"
#include "../sync.h"
#include "primitives.h"
#include "sparkname.h"

namespace spark_mintspend { struct spark_mintspend_test; }

class CCoinsViewCache;
class CTxMemPool;

namespace spark {

/**
 * Registry effects of transactions checked against the registry but not applied to it yet:
 * the earlier transactions of a block being connected, or the mempool.
 */
struct CSparkAssetPending {
    std::set<std::string> symbols;          //!< normalized symbols with an operation
    std::set<std::uint64_t> opAssetTypes;   //!< registered assets with a modify or transfer
    CAssetState::CirculatingSupplyMap minted;
    CAssetState::CirculatingSupplyMap burned;
};

/** Registry effects of one transaction. */
struct CSparkAssetTxEffects {
    std::optional<CSparkAssetTxData> op;
    std::optional<std::uint64_t> opAssetType;   //!< set for modify and transfer
    CAssetState::CirculatingSupplyMap minted;
    CAssetState::CirculatingSupplyMap burned;

    bool IsEmpty() const { return !op && minted.empty() && burned.empty(); }
};

void AddSparkAssetEffects(CSparkAssetPending& pending, const CSparkAssetTxEffects& effects);
void RemoveSparkAssetEffects(CSparkAssetPending& pending, const CSparkAssetTxEffects& effects);

// Spark transaction info, added to the CBlock to ensure spark mint/spend transactions got their info stored into index
class CSparkTxInfo {
public:
    // all the spark transactions encountered so far
    std::set<uint256> spTransactions;

    // Vector of all mints
    std::vector<spark::Coin> mints;

    // linking tag for every spend (map from lTag to coin group id)
    std::unordered_map<GroupElement, int> spentLTags;
    std::unordered_map<uint256, uint256> ltagTxhash;

    // spark names
    std::map<std::string, CSparkNameTxData> sparkNames;

    // spark asset operations in block order, and everything the block does to the registry
    std::vector<std::pair<uint256, CSparkAssetTxData>> assetOps;
    CSparkAssetPending assetPending;

    // information about transactions in the block is complete
    bool fInfoIsComplete = false;

    CSparkTxInfo() = default;

    // finalize everything
    void Complete();
};

// check if spark activation block is passed
bool IsSparkAllowed();
bool IsSparkAllowed(int height);
bool IsSpatsStarted();
bool IsSpatsStarted(int height);
unsigned char GetNetworkType();

// Pass Scripts form mint transaction and get spark MintTransaction object
void ParseSparkMintTransaction(const std::vector<CScript>& scripts, MintTransaction& mintTransaction);
void ParseSpatsMintTransaction(const CScript& script, MintTransaction& mintTransaction, spark::OwnershipProof& ownershipProof, bool* pfMintOnlyWithoutSparkProof = nullptr);
bool ParseSpatsBurn(const CScript& script, std::pair<Scalar, Scalar>& assetId, CAmount& amount);
void ParseSparkMintCoin(const CScript& script, spark::Coin& txCoin);
std::vector<unsigned char> getSerialContext(const CTransaction &tx);
spark::SpendTransaction ParseSparkSpend(const CTransaction &tx);
spats::SpendTransaction ParseSpatsSpend(const CTransaction &tx);

Scalar GetSpatsMintM(const CTransaction& tx);

/**
 * Bind a SPATSMINT output to the spend that authorizes it.
 * scriptPrefix is OP_SPATSMINT followed by the serialized mint coin, without the ownership suffix.
 */
uint256 GetSpatsMintSpendBindHash(CAmount nValue, const std::vector<unsigned char>& scriptPrefix);
CAmount GetSparkSpendFee(const CTransaction& tx);

/**
 * Asset operation carried at the end of the payload, if any.
 * @throws std::invalid_argument if the payload has trailing bytes that are not a canonical asset operation
 */
std::optional<CSparkAssetTxData> GetSparkAssetTxData(const CTransaction& tx);

/**
 * Message signed by a Spark admin: the whole transaction with the asset ownership proof cleared.
 * @pre assetData is the operation at the end of tx.vExtraPayload
 */
Scalar GetSpatsAssetOwnershipM(const CTransaction& tx, const CSparkAssetTxData& assetData);
uint256 GetSpatsAssetOwnershipHash(const CTransaction& tx, const CSparkAssetTxData& assetData);

/**
 * Check asset operations, mints and burns against the registry at the start of the block.
 * Registry ops ride on a Spark spend (the coin owner spends). Register, modify,
 * and transfer must carry an ownership proof for the declared admin address.
 * A burn is a SPATS spend of the asset coins; after it is mined, circulating
 * supply is reduced. A transparent
 * admin mint still spends one of its P2PK/P2PKH coins with SIGHASH_ALL.
 * @param[in] inputs Coins spent by tx; unused for Spark spends
 * @param[in] pending Effects of transactions already accepted into the same block or mempool
 * @param[out] effects What tx does to the registry
 */
bool CheckSparkAssetTransaction(
        const CTransaction& tx,
        const CCoinsViewCache& inputs,
        CValidationState& state,
        int nHeight,
        bool isVerifyDB,
        bool isMempoolAcceptance,
        const CSparkAssetPending& pending,
        CSparkAssetTxEffects& effects);

/** Track the registry effects of a transaction entering or leaving the mempool. */
void AddSparkAssetTxToMempool(CTxMemPool& pool, const uint256& hash, const CSparkAssetTxEffects& effects);
void RemoveSparkAssetTxFromMempool(CTxMemPool& pool, const uint256& hash);

std::vector<GroupElement>  GetSparkUsedTags(const CTransaction &tx);
std::vector<spark::Coin>  GetSparkMintCoins(const CTransaction &tx);
CAmount GetSparkFee(const CTransaction &tx);

size_t GetSpendInputs(const CTransaction &tx);
/** Transparent FIRO withdrawn by a Spark spend. Skips Spark/SPATS mint and burn outputs. */
CAmount GetSpendTransparentAmount(const CTransaction& tx);

/** Whether a Spark spend has a format mineable at the given block height. */
bool IsSparkSpendFormatAllowed(const CTransaction& tx, int height);

bool CheckSparkBlock(CValidationState &state, const CBlock& block, int nBlockHeight);

/** Reject repeated Spark coin identities within a block or at an earlier height. */
bool CheckSparkMintDuplicates(
        CValidationState& state,
        const std::vector<spark::Coin>& mints,
        int nHeight);

//void DisconnectTipLelantus(CBlock &block, CBlockIndex *pindexDelete);

bool ConnectBlockSpark(
        CValidationState& state,
        const CChainParams& chainparams,
        CBlockIndex* pindexNew,
        const CBlock *pblock,
        bool fJustCheck=false,
        bool isVerifyDB=false);

bool DisconnectTipSpark(CBlock &block, CBlockIndex *pindexDelete);

/** Drop a cached successful proof when the tx leaves the mempool. */
void EraseCheckedSparkSpendTransaction(const uint256& hashTx);

/** Clear proof results that depend on active-chain cover-set data. */
void ClearSparkSpendProofCache();

/** Current number of cached successful proofs. */
std::size_t GetSparkSpendProofCacheSize();



bool CheckSparkTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo);

bool GetOutPoint(COutPoint& outPoint, const spark::Coin& coin);
bool GetOutPoint(COutPoint& outPoint, const uint256& coinHash);
/**
 * @param[out] txOut If non-null, reset on entry and set to the transaction
 * containing the coin on success.
 * @return true if the coin was found in the block.
 */
bool GetOutPointFromBlock(COutPoint& outPoint, const spark::Coin& coin, const CBlock &block, CTransactionRef* txOut = nullptr);

bool BuildSparkStateFromIndex(CChain *chain);

class CSparkMempoolState {
private:
    // mints in the mempool
    std::unordered_map<uint256, uint256> mempoolMints;

    // linking tags of spends currently in the mempool mapped to tx hashes
    std::unordered_map<GroupElement, uint256, spark::CLTagHash> mempoolLTags;

    // asset state in mempool
    CAssetState asset_state_;


public:
    // Check if there is a conflicting tx in the blockchain or mempool
    bool HasMint(const spark::Coin& coin);
    void AddMintToMempool(const spark::Coin& coin, const uint256& txHash);
    void RemoveMintFromMempool(const spark::Coin& coin);
    uint256 GetMempoolConflictingMintTxHash(const spark::Coin& coin);

    // Check if there is a conflicting tx in the blockchain or mempool
    bool HasLTag(const GroupElement& lTag);

    // Add spend into the mempool.
    bool AddSpendToMempool(const GroupElement& lTag, uint256 txHash);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const GroupElement& lTag);

    // Get conflicting tx hash by coin serial number
    uint256 GetMempoolConflictingTxHash(const GroupElement& lTag);

    std::unordered_map<GroupElement, uint256, spark::CLTagHash> const & GetMempoolLTags() const { return mempoolLTags; }

    const CAssetState& GetAssetState() const noexcept { return asset_state_; }

    void Reset();
};

/*
 * State of minted/spent coins as extracted from the index
 */
class CSparkState {
public:
    // First and last block where mint with given id was seen
    struct SparkCoinGroupInfo {
        SparkCoinGroupInfo() : firstBlock(nullptr), lastBlock(nullptr), nCoins(0) {}

        // first and last blocks having coins with given id minted
        CBlockIndex *firstBlock;
        CBlockIndex *lastBlock;
        // total number of minted coins with such parameters
        int nCoins;
    };

public:
    CSparkState(
            size_t maxCoinInGroup = ZC_SPARK_MAX_MINT_NUM,
            size_t startGroupSize = ZC_SPARK_SET_START_SIZE);
    CSparkState(const CSparkState&) = delete;
    CSparkState& operator=(const CSparkState&) = delete;

    /**
     * Copy live Spark state into this instance without copying the mutex.
     * Used by VerifyDB to snapshot the node state into an isolated context.
     */
    void CopyFrom(const CSparkState& other);

    // Reset to initial values
    void Reset();

    // Query if the coin linking tag was previously used
    bool IsUsedLTag(const GroupElement& lTag);
    // Query if the hash of a linking tag was previously used. If so, store preimage in coinSerial param
    bool IsUsedLTagHash(GroupElement& lTag, const uint256 &coinLTaglHash);

    // Return height of mint transaction and id of minted coin
    std::pair<int, int> GetMintedCoinHeightAndId(const spark::Coin& coin);

    // Query if there is a coin with given pubCoin value
    bool HasCoin(const spark::Coin& coin);

    /** True when a minted coin with this serial commitment and value commitment is in the chain state. */
    bool HasCoinSerialAndCommitment(const secp_primitives::GroupElement& serial, const secp_primitives::GroupElement& commitment) const;

    // Query if there is a coin with given hash of a coin value.
    bool HasCoinHash(spark::Coin& coin, const uint256& coinHash);

    // Query coin group with given id
    bool GetCoinGroupInfo(int group_id, SparkCoinGroupInfo &result);

    int GetLatestCoinID() const;

    // Check if there is a conflicting tx in the blockchain or mempool
    bool CanAddSpendToMempool(const GroupElement& lTag);

    bool CanAddMintToMempool(const spark::Coin& coin);

    bool AddMint(const spark::Coin& coin, const CMintedCoinInfo& coinInfo);
    bool RemoveMint(const spark::Coin& coin, int expectedGroupId, int expectedHeight);
    // Add mints in block, automatically assigning id to it
    void AddMintsToStateAndBlockIndex(CBlockIndex *index, const CBlock* pblock);

    void AddSpend(const GroupElement& lTag, int coinGroupId);
    void AddLTagTxHash(const uint256& lTagHash, const uint256& txHash);
    void RemoveSpend(const GroupElement& lTag);
    // Add everything from the block to the state
    bool AddBlock(CBlockIndex *index);
    // Disconnect block from the chain rolling back mints and spends
    bool RemoveBlock(CBlockIndex *index);
    /**
     * Record the block's asset registry changes in its index entry, then apply them.
     * A modify or transfer for an unknown symbol fails without changing the registry.
     */
    bool ConnectAssetBlock(CBlockIndex *index, const CSparkTxInfo& info);

    // Add spend into the mempool.
    // Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const std::vector<GroupElement>& lTags, uint256 txHash);

    void AddMintsToMempool(
        const std::vector<spark::Coin>& coins,
        const uint256& txHash);
    void RemoveMintFromMempool(const spark::Coin& coin);

    // Get conflicting tx hash by coin linking tag
    uint256 GetMempoolConflictingTxHash(const GroupElement& lTag);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const std::vector<GroupElement>& lTags);

    // Given id returns the latest anonymity set and corresponding block hash
    // Do not take into account coins with height more than maxHeight
    // Returns number of coins satisfying conditions
    void GetCoinSet(
            int coinGroupID,
            std::vector<spark::Coin>& coins_out);

    int GetCoinSetForSpend(
            CChain *chain,
            int maxHeight,
            int id,
            uint256& blockHash_out,
            std::vector<spark::Coin>& coins_out,
            std::vector<unsigned char>& setHash_out);

    void GetCoinsForRecovery(
            CChain *chain,
            int maxHeight,
            int coinGroupID,
            std::string start_block_hash,
            uint256& blockHash_out,
            std::vector<std::pair<spark::Coin, std::pair<uint256, std::vector<unsigned char>>>>& coins,
            std::vector<unsigned char>& setHash_out);

    void GetAnonSetMetaData(
            CChain *chain,
            int maxHeight,
            int coinGroupID,
            uint256& blockHash_out,
            std::vector<unsigned char>& setHash_out,
            int& size);

    void GetCoinsForRecovery(
            CChain *chain,
            int maxHeight,
            int coinGroupID,
            int startIndex,
            int endIndex,
            uint256& blockHash,
            std::vector<std::pair<spark::Coin, std::pair<uint256, std::vector<unsigned char>>>>& coins);

    std::unordered_map<spark::Coin, CMintedCoinInfo, spark::CoinHash> GetMints() const;
    std::unordered_map<GroupElement, int, spark::CLTagHash> const & GetSpends() const;
    std::vector<std::pair<GroupElement, int>> const & GetSpendsMobile() const;
    std::unordered_map<uint256, uint256> const& GetSpendTxIds() const;
    std::unordered_map<int, SparkCoinGroupInfo> const & GetCoinGroups() const;
    std::unordered_map<GroupElement, uint256, spark::CLTagHash> const & GetMempoolLTags() const;

    static CSparkState* GetState();

    std::size_t GetTotalCoins() const;

    const CAssetState& GetAssetState() const noexcept { return asset_state_; }

private:
    size_t CountLastNCoins(int groupId, size_t required, CBlockIndex* &first);
    bool ApplyAssetBlock(const CBlockIndexPrivacyData& pd);
    bool UndoAssetBlock(const CBlockIndexPrivacyData& pd);

private:
    // Group Limit
    size_t maxCoinInGroup;
    size_t startGroupSize;

    // Latest anonymity set id;
    int latestCoinId;

    // Collection of coin groups. Map from id to LelantusCoinGroupInfo structure
    std::unordered_map<int, SparkCoinGroupInfo> coinGroups;

    // Set of all minted coins
    mutable CCriticalSection cs_minted_coins;
    std::unordered_map<spark::Coin, CMintedCoinInfo, spark::CoinHash> mintedCoins GUARDED_BY(cs_minted_coins);
    // Serial commitment S to value commitment C, kept beside mintedCoins.
    std::unordered_map<secp_primitives::GroupElement, secp_primitives::GroupElement, spark::CLTagHash> mintedSerialCommitments GUARDED_BY(cs_minted_coins);
    // Set of all used coin linking tags.
    std::unordered_map<GroupElement, int, spark::CLTagHash> usedLTags;
    // Set of all used linking tags, used only when -mobile=true
    std::vector<std::pair<GroupElement, int>> mobileUsedLTags;
    // linking tag hash mapped to tx hash
    std::unordered_map<uint256, uint256> ltagTxhash;

    typedef std::map<int, size_t> metainfo_container_t;
    metainfo_container_t extendedMintMetaInfo, mintMetaInfo, spendMetaInfo;


    CAssetState asset_state_;

    friend struct spark_mintspend::spark_mintspend_test;
};

/**
 * Isolated Spark state used while VerifyDB reconnects blocks. The active
 * context is thread-local so validation can use it without changing the live
 * node state that VerifyDB is auditing.
 */
class CSparkVerifyDBContext {
public:
    explicit CSparkVerifyDBContext(CBlockIndex* tip);
    ~CSparkVerifyDBContext();

    CSparkVerifyDBContext(const CSparkVerifyDBContext&) = delete;
    CSparkVerifyDBContext& operator=(const CSparkVerifyDBContext&) = delete;

    void AddBlock(CBlockIndex* index);

    CSparkState& GetSparkState() { return state; }
    CSparkNameManager& GetSparkNameManager() { return sparkNameManager; }

    static CSparkVerifyDBContext* GetActive();

private:
    CSparkState state;
    CSparkNameManager sparkNameManager;
    CSparkVerifyDBContext* previous;
};

} // namespace spark

#endif //_MAIN_SPARK_STATE_H_
