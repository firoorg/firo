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
#include "../spats/wallet.hpp"

class CRecipient;
class CReserveKey;
class CCoinControl;
extern CChain chainActive;

const uint32_t BIP44_SPARK_INDEX = 0x6;
const uint32_t SPARK_CHANGE_D = 0x270F;

class CSparkWallet {
public:
    explicit CSparkWallet(const std::string& strWalletFile);
    ~CSparkWallet();

    spats::Wallet& getSpatsWallet() noexcept { return spats_wallet_; }

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

    CAmount getAddressFullBalance(const spark::Address& address) const;
    CAmount getAddressAvailableBalance(const spark::Address& address) const;
    CAmount getAddressUnconfirmedBalance(const spark::Address& address) const;

    spats::Wallet::asset_balances_t getAssetBalances() const;

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
    void RemoveSparkSpends(const std::unordered_map<GroupElement, int>& spends);
    void AbandonSparkMints(const std::vector<spark::Coin>& mints);
    void AbandonSpends(const std::vector<GroupElement>& spends);

    // get the vector of mint metadata for a single address
    // ATTENTION: this will return spats coins too, at least for now!
    std::vector<CSparkMintMeta> listAddressCoins(int32_t i, bool fUnusedOnly = false) const;

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
            const CCoinControl *coinControl,
            bool autoMintAll = false);

    CWalletTx CreateSparkSpendTransaction(
            const std::vector<CRecipient>& recipients,
            const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients,
            const std::vector<spark::OutputCoinData>& spatsRecipients,
            CAmount &fee,
            const CCoinControl *coinControl = nullptr);

	void AppendSpatsMintTxData(CMutableTransaction& tx,
        const std::pair<spark::MintedCoinData, spark::Address>& spatsRecipient, // .second is the initiator's (i.e. admin's) address
        const spark::SpendKey& spendKey);

    CWalletTx CreateSpatsMintTransaction(
            const std::pair<spark::MintedCoinData, spark::Address>& spatsRecipient,
            CAmount &fee,
            const CCoinControl *coinControl = nullptr);

    std::pair<CAmount, std::vector<CSparkMintMeta>> SelectSparkCoins(
            CAmount required,
            bool subtractFeeFromAmount,
            std::list< CSparkMintMeta> coins,
            std::size_t mintNum,
            std::size_t utxoNum,
            const CCoinControl *coinControl,
            std::size_t spats_script_sizes_total = 0);

    bool GetCoinsToSpend(
        CAmount required,
        std::vector<CSparkMintMeta>& coinsToSpend_out,
        std::list<CSparkMintMeta> coins,
        int64_t& changeToMint,
        const CCoinControl *coinControl,
        bool fSpats = false);

    // Filters coins by identifier, returns all available coins for a specific asset
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

    void* threadPool;

    spats::Wallet spats_wallet_;

    void notifyCoinMetasChanged(bool potential_spats_coin_change = true);
};

#endif //FIRO_SPARK_WALLET_H
