// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_WALLET_H
#define FIRO_SPARK_WALLET_H

#include "primitives.h"
#include "../libspark/keys.h"
#include "../libspark/mint_transaction.h"
#include "../libspark/spend_transaction.h"
#include "../wallet/walletdb.h"
#include "../sync.h"
#include "../chain.h"

struct CRecipient;
class CReserveKey;
class CCoinControl;
extern CChain chainActive;

const uint32_t BIP44_SPARK_INDEX = 0x6;
const uint32_t SPARK_CHANGE_D = 0x270F;

class CSparkWallet  {
public:
    CSparkWallet(const std::string& strWalletFile);
    ~CSparkWallet();
    // increment diversifier and generate address for that
    spark::Address generateNextAddress();
    spark::Address generateNewAddress();
    spark::Address getDefaultAddress();
    spark::Address getChangeAddress();
    // assign difersifier to the value from db
    void resetDiversifierFromDB(CWalletDB& walletdb);
    // assign diversifier in to to current value
    void updatetDiversifierInDB(CWalletDB& walletdb);

    // functions for key set generation
    spark::SpendKey generateSpendKey(const spark::Params* params);
    spark::FullViewKey generateFullViewKey(const spark::SpendKey& spend_key);
    spark::IncomingViewKey generateIncomingViewKey(const spark::FullViewKey& full_view_key);

    // get map diversifier to Address
    std::unordered_map<int32_t, spark::Address> getAllAddresses();
    // get address for a diversifier
    spark::Address getAddress(const int32_t& i);
    bool isAddressMine(const std::string& encodedAddr);
    bool isAddressMine(const spark::Address& address);
    bool isChangeAddress(const uint64_t& i) const;

    // list spark mint, mint metadata in memory and in db should be the same at this moment, so get from memory
    std::vector<CSparkMintMeta> ListSparkMints(bool fUnusedOnly = false, bool fMatureOnly = false) const;
    std::list<CSparkSpendEntry> ListSparkSpends() const;
    std::unordered_map<uint256, CSparkMintMeta> getMintMap() const;
    // generate spark Coin from meta data
    spark::Coin getCoinFromMeta(const CSparkMintMeta& meta) const;
    spark::Coin getCoinFromLTag(const GroupElement& lTag) const;
    spark::Coin getCoinFromLTagHash(const uint256& lTagHash) const;

    // functions to get spark balance
    CAmount getFullBalance();
    CAmount getAvailableBalance();
    CAmount getUnconfirmedBalance();
    std::pair<CAmount, CAmount> getSparkBalance();

    CAmount getAddressFullBalance(const spark::Address& address);
    CAmount getAddressAvailableBalance(const spark::Address& address);
    CAmount getAddressUnconfirmedBalance(const spark::Address& address);

    // function to be used for zap wallet
    void clearAllMints(CWalletDB& walletdb);
    // erase mint meta data from memory and from db
    void eraseMint(const uint256& hash, CWalletDB& walletdb);
    // add mint meta data to memory and to db
    void addOrUpdateMint(const CSparkMintMeta& mint, const uint256& lTagHash, CWalletDB& walletdb);
    void updateMint(const CSparkMintMeta& mint, CWalletDB& walletdb);

    void setCoinUnused(const  GroupElement& lTag);

    void updateMintInMemory(const CSparkMintMeta& mint);
    // get mint meta from linking tag hash
    CSparkMintMeta getMintMeta(const uint256& hash);
    // get mint tag from nonce
    CSparkMintMeta getMintMeta(const secp_primitives::Scalar& nonce);
    bool getMintMeta(spark::Coin coin, CSparkMintMeta& mintMeta);

    bool getMintAmount(spark::Coin coin, CAmount& amount);

    bool isMine(spark::Coin coin) const;
    bool isMine(const std::vector<GroupElement>& lTags) const;

    CAmount getMyCoinV(spark::Coin coin) const;
    CAmount getMySpendAmount(const std::vector<GroupElement>& lTags) const;
    bool getMyCoinIsChange(spark::Coin coin) const;
    spark::Address getMyCoinAddress(spark::Coin coin);

    void UpdateSpendState(const GroupElement& lTag, const uint256& lTagHash, const uint256& txHash, bool fUpdateMint = true);
    void UpdateSpendState(const GroupElement& lTag, const uint256& txHash, bool fUpdateMint = true);
    void UpdateSpendStateFromMempool(const std::vector<GroupElement>& lTags, const uint256& txHash, bool fUpdateMint = true);
    void UpdateSpendStateFromBlock(const CBlock& block);
    void UpdateMintState(const std::vector<spark::Coin>& coins, const uint256& txHash, CWalletDB& walletdb);
    void UpdateMintStateFromMempool(const std::vector<spark::Coin>& coins, const uint256& txHash);
    void UpdateMintStateFromBlock(const CBlock& block);
    void RemoveSparkMints(const std::vector<spark::Coin>& mints);
    void RemoveSparkSpends(const std::unordered_map<GroupElement, int>& spends);
    void AbandonSparkMints(const std::vector<spark::Coin>& mints);
    void AbandonSpends(const std::vector<GroupElement>& spends);

    // get the vector of mint metadata for a single address
    std::vector<CSparkMintMeta> listAddressCoins(const int32_t& i, bool fUnusedOnly = false);

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

    CWalletTx CreateSparkSpendTransaction(
            const std::vector<CRecipient>& recipients,
            const std::vector<std::pair<spark::OutputCoinData, bool>>&  privateRecipients,
            CAmount &fee,
            const CCoinControl *coinControl = NULL,
            CAmount additionalTxSize = 0);

    std::pair<CAmount, std::vector<CSparkMintMeta>> SelectSparkCoins(
            CAmount required,
            bool subtractFeeFromAmount,
            std::list< CSparkMintMeta> coins,
            std::size_t mintNum,
            std::size_t utxoNum,
            const CCoinControl *coinControl,
            size_t additionalTxSize = 0);

    CWalletTx CreateSparkNameTransaction(
            CSparkNameTxData &nameData,
            CAmount sparkNamefee,
            CAmount &txFee,
            const CCoinControl *coinControl = NULL);

    // Returns the list of pairs of coins and metadata for that coin,
    std::list<CSparkMintMeta> GetAvailableSparkCoins(const CCoinControl *coinControl = NULL) const;

    void FinishTasks();

public:
    // to protect coinMeta
    mutable CCriticalSection cs_spark_wallet;

private:
    std::string strWalletFile;
    // this is latest used diversifier
    int32_t lastDiversifier;

    // this is full view key, which is saved into db
    spark::FullViewKey fullViewKey;
    // this is incoming view key
    spark::IncomingViewKey viewKey;

    // map diversifier to address.
    std::unordered_map<int32_t, spark::Address> addresses;

    // map lTagHash to coin meta
    std::unordered_map<uint256, CSparkMintMeta> coinMeta;

    // Lookup indexes into coinMeta (values are its lTagHash keys), so that
    // wallet-known coins are resolved by hash lookup instead of trial
    // decryption or a linear scan. Guarded by cs_spark_wallet and maintained
    // wherever coinMeta is mutated.
    std::unordered_map<uint256, uint256> coinLookup;  // GetSparkCoinHash(meta.coin) -> lTagHash
    std::unordered_map<uint256, uint256> nonceLookup; // GetNonceHash(meta.k) -> lTagHash

    // when true (-sparkcacheverify), every lookup index hit is cross-checked
    // against identification and rejected on divergence
    bool fCacheAudit{false};

    void addToLookups(const uint256& lTagHash, const CSparkMintMeta& mint);
    void removeFromLookups(const uint256& lTagHash, const CSparkMintMeta& mint);
    /**
     * Return the recorded meta for a wallet-known coin, or nullptr.
     * A non-null result requires full coin equality plus an equal serial
     * context, so the answer matches what identification would produce.
     * @pre cs_spark_wallet is held; the pointer is valid only under it
     */
    const CSparkMintMeta* findMintMeta(const spark::Coin& coin) const;

    void* threadPool;
};


#endif //FIRO_SPARK_WALLET_H
