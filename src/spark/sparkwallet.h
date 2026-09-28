// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_WALLET_H
#define FIRO_SPARK_WALLET_H

#include "primitives.h"
#include "../libspark/keys.h"
#include "../libspark/mint_transaction.h"
#include "../libspark/spend_transaction.h"
#include <optional>
#include "../wallet/walletdb.h"
#include "../sync.h"
#include "../sparkname.h"
#include "sparkasset.h"
#include "../chain.h"

struct CRecipient;
class CReserveKey;
class CCoinControl;
extern CChain chainActive;

const uint32_t BIP44_SPARK_INDEX = 0x6;
const uint32_t SPARK_CHANGE_D = 0x270F;
const Scalar ZERO = Scalar((uint64_t)0);

class CSparkWallet {
public:
    explicit CSparkWallet(const std::string& strWalletFile);
    ~CSparkWallet();

    // increment diversifier and generate address for that
    spark::Address generateNextAddress();
    spark::Address generateNewAddress();
    spark::Address getDefaultAddress();
    spark::Address getChangeAddress() const;

    spark::OwnershipProof makeDefaultAddressOwnershipProof(const secp_primitives::Scalar& m);

    // assign diversifier to the value from db
    void resetDiversifierFromDB(CWalletDB& walletdb);
    // assign diversifier in to to current value
    void updateDiversifierInDB(CWalletDB& walletdb) const;

    // functions for key set generation
    spark::SpendKey generateSpendKey(const spark::Params* params);
    spark::FullViewKey generateFullViewKey(const spark::SpendKey& spend_key) const;
    spark::IncomingViewKey generateIncomingViewKey(const spark::FullViewKey& full_view_key);

    // generates and returns a valid SpendKey, otherwise throws std::runtime_error
    spark::SpendKey ensureSpendKey();

    // get map diversifier to Address
    std::unordered_map<int32_t, spark::Address> getAllAddresses() const;
    // get address for a diversifier
    spark::Address getAddress(int32_t i) const;
    bool isAddressMine(const std::string& encodedAddr) const;
    bool isAddressMine(const spark::Address& address) const;
    bool isChangeAddress(const uint64_t& i) const;

    // Decodes the given `encoded_address` into a spark::Address, using the default spark Params.
    // Returns: the decoded address.
    // Throws: a std::exception-derived exception in case of failure, such as an invalid encoded address supplied.
    static spark::Address decodeAddress(const std::string& encoded_address);

    // Sign a message with one of our addresses, returning the ownership proof as hex.
    // Throws WalletLocked if the spend key cannot be generated because the wallet is
    // locked, or std::runtime_error if the address is not ours or the key generation
    // fails for any other reason.
    std::string SignMessage(const spark::Address& address, const std::string& message);

    // list spark mint, mint metadata in memory and in db should be the same at this moment, so get from memory
    std::vector<CSparkMintMeta> ListSparkMints(bool fUnusedOnly = false, bool fMatureOnly = false) const;
    std::list<CSparkSpendEntry> ListSparkSpends() const;

    // ATTENTION: this will return spats coins too, at least for now!
    std::unordered_map<uint256, CSparkMintMeta> getMintMap() const;

    // generate spark Coin from meta data
    spark::Coin getCoinFromMeta(const CSparkMintMeta& meta) const;
    spark::Coin getCoinFromLTag(const GroupElement& lTag) const;
    spark::Coin getCoinFromLTagHash(const uint256& lTagHash) const;

    // functions to get spark balance
    CAmount getFullBalance() const;
    CAmount getAvailableBalance() const;
    CAmount getUnconfirmedBalance() const;
    std::pair<CAmount, CAmount> getSparkBalance();

    CAmount getAddressFullBalance(const spark::Address& address) const;
    CAmount getAddressAvailableBalance(const spark::Address& address) const;
    CAmount getAddressUnconfirmedBalance(const spark::Address& address) const;

    // function to be used for zap wallet
    void clearAllMints(CWalletDB& walletdb);
    // erase mint metadata from memory and from db
    void eraseMint(const uint256& hash, CWalletDB& walletdb);
    // add mint metadata to memory and to db
    void addOrUpdateMint(const CSparkMintMeta& mint, const uint256& lTagHash, CWalletDB& walletdb);
    void updateMint(const CSparkMintMeta& mint, CWalletDB& walletdb);

    void setCoinUnused(const GroupElement& lTag);

    void updateMintInMemory(const CSparkMintMeta& mint);
    // get mint meta from linking tag hash
    CSparkMintMeta getMintMeta(const uint256& hash) const;
    // get mint tag from nonce
    CSparkMintMeta getMintMeta(const secp_primitives::Scalar& nonce) const;
    bool getMintMeta(spark::Coin coin, CSparkMintMeta& mintMeta) const;

    bool getMintAmount(spark::Coin coin, CAmount& amount) const;

    bool isMine(spark::Coin coin) const;
    bool isMine(const std::vector<GroupElement>& lTags) const;

    CAmount getMyCoinV(spark::Coin coin) const;
    CAmount getMySpendAmount(const std::vector<GroupElement>& lTags) const;
    bool getMyCoinIsChange(spark::Coin coin) const;
    spark::Address getMyCoinAddress(spark::Coin coin) const;

    void UpdateSpendState(const GroupElement& lTag, const uint256& lTagHash, const uint256& txHash, bool fUpdateMint = true);
    void UpdateSpendState(const GroupElement& lTag, const uint256& txHash, bool fUpdateMint = true);
    void UpdateSpendStateFromMempool(const std::vector<GroupElement>& lTags, const uint256& txHash, bool fUpdateMint = true);
    void UpdateSpendStateFromBlock(const CBlock& block);
    void UpdateMintState(const std::vector<spark::Coin>& coins, const uint256& txHash, CWalletDB& walletdb);
    void UpdateMintStateFromMempool(const std::vector<spark::Coin>& coins, const uint256& txHash);
    void UpdateMintStateFromBlock(const CBlock& block);
    void RemoveSparkMints(const std::vector<spark::Coin>& mints);
    // mark the coins of the given linking tags as unspent again
    void RemoveSparkSpends(const std::vector<GroupElement>& lTags);
    void AbandonSparkMints(const std::vector<spark::Coin>& mints);
    void AbandonSpends(const std::vector<GroupElement>& spends);

    // get the vector of mint metadata for a single address
    // ATTENTION: this will return spats coins too, at least for now!
    std::vector<CSparkMintMeta> listAddressCoins(const int32_t i, bool fUnusedOnly = false) const;

    /**
     * Re-run identification on every cached mint and evict the lookup index
     * entries of records the cryptography does not confirm, so queries on
     * them fall back to full identification instead of trusting the record.
     * Unspent records are verified first. Runs on the thread pool after the
     * constructor loads a non-empty wallet; stops early on shutdown.
     * @return number of records evicted from the lookup indexes
     */
    size_t verifyCachedCoins();
    // check that the lookup indexes and coinMeta describe each other exactly
    bool validateLookupIndexes() const;


    // generate recipient data for mint transaction,
    static std::vector<CRecipient> CreateSparkMintRecipients(
            const std::vector<spark::MintedCoinData>& outputs,
            const std::vector<unsigned char>& serial_context,
            bool generate);

    bool CreateSparkMintTransactions(
            const std::vector<spark::MintedCoinData>& outputs,
            std::vector<std::pair<CWalletTx,
            CAmount>>& wtxAndFee,
            CAmount& nAllFeeRet,
            std::list<CReserveKey>& reservekeys,
            int& nChangePosInOut,
            bool subtractFeeFromAmount,
            std::string& strFailReason,
            bool fSplit,
            const CCoinControl *coinControl,
            bool autoMintAll = false);

    /**
     * Build a Spark spend. Chaum V2 is selected when the next block is at or
     * past nSparkChaumV2StartBlock.
     * @param[in] recipients Transparent outputs.
     * @param[in] privateRecipients Private outputs and whether each pays the fee.
     * @param[out] fee Selected fee in satoshis.
     * @param[in] coinControl Optional per-send fee and coin-selection overrides; may be null.
     * @param[in] additionalTxSize Extra serialized bytes included in the fee estimate.
     * @param[in] extensionCommitment V2 spend extension commitment; ignored for V1.
     * @param[in] expectedNextBlockHeight Caller snapshot of chainActive.Height()+1.
     *     If >= 0, it must still match at construction or the call throws.
     *     The default -1 skips that check.
     * @param[out] recipientAmounts Optional caller-owned vector. If non-null it
     *     is overwritten with post-fee amounts (transparent, then private).
     *     The wallet does not take ownership of the container.
     * @return The constructed wallet transaction.
     * @pre pwalletMain is unlocked.
     */
    CWalletTx CreateSparkSpendTransaction(
            const std::vector<CRecipient>& recipients,
            const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients,
            const std::vector<spark::OutputCoinData>& spatsRecipients,
            CAmount &fee,
            const std::pair<CAmount, std::pair<Scalar, Scalar>> &burnAsset,
            const CCoinControl *coinControl = nullptr,
            std::size_t additionalTxSize = 0,
            const uint256& extensionCommitment = uint256(),
            int expectedNextBlockHeight = -1,
            std::vector<CAmount>* recipientAmounts = nullptr,
            const uint256& extraDataHash = uint256());

    void AppendSpatsMintTxData(CMutableTransaction& tx,
        const std::pair<spark::MintedCoinData, spark::Address>& spatsRecipient,
        const spark::SpendKey& spendKey);

    CWalletTx CreateSpatsMintTransaction(
        const std::pair<spark::MintedCoinData, spark::Address>& spatsRecipient,
        CAmount &fee,
        const CCoinControl *coinControl = nullptr);

    /**
     * Select Spark coins and the matching fee for a spend.
     * @param[in] required Amount to cover before or after fee depending on subtractFeeFromAmount.
     * @param[in] subtractFeeFromAmount If true, fee is taken from outputs instead of added to required.
     * @param[in] coins Candidate mint metadata.
     * @param[in] mintNum Private outputs used in the size model.
     * @param[in] utxoNum Transparent outputs used in the size model.
     * @param[in] coinControl Optional fee overrides; may be null.
     * @param[in] useChaumV2 If true, apply V2 input-count and size-model extras.
     * @param[in] additionalTxSize Extra bytes included in the size estimate.
     * @return The selected fee and the coins to spend.
     */
    std::pair<CAmount, std::vector<CSparkMintMeta>> SelectSparkCoins(
            CAmount required,
            bool subtractFeeFromAmount,
            std::list<CSparkMintMeta> coins,
            std::size_t mintNum,
            std::size_t utxoNum,
            const CCoinControl *coinControl,
            bool useChaumV2,
            size_t additionalTxSize = 0);

    std::pair<CAmount, std::vector<CSparkMintMeta>> SelectSparkCoinsNew(
        CAmount required,
        CAmount spatsRequired,
        const std::pair<Scalar, Scalar>& identifier,
        bool subtractFeeFromAmount,
        std::size_t mintNum,
        std::size_t utxoNum,
        std::vector<CSparkMintMeta>& spatsSpendCoins,
        const CCoinControl *coinControl,
        size_t additionalTxSize = 0);

    bool GetCoinsToSpend(
        CAmount required,
        std::vector<CSparkMintMeta>& coinsToSpend_out,
        std::list<CSparkMintMeta> coins,
        int64_t& changeToMint,
        const CCoinControl *coinControl,
        bool fSpats = false);

    /**
     * Build a Spark name transaction using the next block's activation rules
     * (name format, fee script, and Chaum V2).
     * @param[in,out] nameData Name payload; filled with height-dependent fields.
     * @param[in] sparkNamefee Transparent name-fee payout amount.
     * @param[out] txFee Selected spend fee in satoshis.
     * @param[in] coinControl Optional fee overrides; may be null.
     * @param[in] expectedNextBlockHeight Caller snapshot of chainActive.Height()+1.
     *     If >= 0, it must still match at construction or the call throws.
     *     The default -1 skips that check.
     * @return The constructed wallet transaction.
     * @pre pwalletMain is unlocked.
     */
    CWalletTx CreateSparkNameTransaction(
            CSparkNameTxData &nameData,
            CAmount sparkNamefee,
            CAmount &txFee,
            const CCoinControl *coinControl = nullptr,
            int expectedNextBlockHeight = -1);

    // used to create asset registration and modification transactions
    CWalletTx CreateSparkAssetTransaction(
        spark::CSparkAssetTxData &assetData,
        CAmount &txFee,
        const CCoinControl *coinControl = nullptr);

    // Filters coins by identifier, returns all available coins for a specific asset
    std::list<CSparkMintMeta> GetAvailableSparkCoins(const CCoinControl *coinControl = nullptr) const;
    std::list<CSparkMintMeta> GetAvailableSparkCoins(const std::pair<Scalar, Scalar>& identifier, const CCoinControl *coinControl = nullptr) const;

    template <typename Pred, typename Visitor>
    requires std::predicate<Pred, const CSparkMintMeta&> && std::invocable<Visitor, const CSparkMintMeta&>
    void VisitCoinMetasWhere(Pred pred, Visitor visitor) const
    {
        LOCK(cs_spark_wallet);
        for (const auto& [hash, meta] : coinMeta)
            if (pred(meta))
                visitor(meta);
    }

    template <typename Pred, typename Visitor>
    requires std::predicate<Pred, const CSparkMintMeta&> && std::invocable<Visitor, const CSparkMintMeta&>
    void VisitUnusedCoinMetasWhere(Pred pred, Visitor visitor) const
    {
        VisitCoinMetasWhere([&pred] (const CSparkMintMeta& meta) { return !meta.isUsed && pred(meta); }, visitor);
    }

    /** Wait for all Spark wallet tasks queued before this call. */
    void WaitForPendingTasks();
    void FinishTasks();

    uint64_t GetNFTIdentifier(const std::string& symbol) const;

    bool NFTIdentifierExists(const std::string& symbol , const std::uint64_t& identifier) const;


public:
    // Protects lastDiversifier, addresses, and coinMeta.
    mutable CCriticalSection cs_spark_wallet;

private:
    struct IdentifiedMint
    {
        CSparkMintMeta meta;
        GroupElement lTag;
    };

    IdentifiedMint IdentifyMint(spark::Coin coin, const uint256& txHash) const;
    void RecordMint(IdentifiedMint mint, CWalletDB& walletdb);

    std::string strWalletFile;
    // this is latest used diversifier
    int32_t lastDiversifier GUARDED_BY(cs_spark_wallet);

    // this is full view key, which is saved into db
    spark::FullViewKey fullViewKey;
    // this is incoming view key
    spark::IncomingViewKey viewKey;

    // map diversifier to address.
    std::unordered_map<int32_t, spark::Address> addresses GUARDED_BY(cs_spark_wallet);

    // map lTagHash to coin meta
    std::unordered_map<uint256, CSparkMintMeta> coinMeta GUARDED_BY(cs_spark_wallet);

    // Lookup indexes into coinMeta (values are its lTagHash keys), so that
    // wallet-known coins are resolved by hash lookup instead of trial
    // decryption or a linear scan. Guarded by cs_spark_wallet and maintained
    // wherever coinMeta is mutated.
    std::unordered_map<uint256, uint256> coinLookup GUARDED_BY(cs_spark_wallet);  // GetSparkCoinHash(meta.coin) -> lTagHash
    std::unordered_map<uint256, uint256> nonceLookup GUARDED_BY(cs_spark_wallet); // GetNonceHash(meta.k) -> lTagHash

    // when true (-sparkcacheverify), every lookup index hit is cross-checked
    // against identification and rejected on divergence
    bool fCacheAudit{false};

    void addToLookups(const uint256& lTagHash, const CSparkMintMeta& mint)
        EXCLUSIVE_LOCKS_REQUIRED(cs_spark_wallet);
    void removeFromLookups(const uint256& lTagHash, const CSparkMintMeta& mint)
        EXCLUSIVE_LOCKS_REQUIRED(cs_spark_wallet);
    /**
     * Return the recorded meta for a wallet-known coin, or nullptr.
     * A non-null result requires full coin equality plus an equal serial
     * context, so the answer matches what identification would produce.
     * @pre cs_spark_wallet is held; the pointer is valid only under it
     */
    const CSparkMintMeta* findMintMeta(const spark::Coin& coin) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_spark_wallet);

    CCriticalSection cs_thread_pool;
    void* threadPool;
};

#endif //FIRO_SPARK_WALLET_H
