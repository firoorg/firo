// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_WALLET_H
#define FIRO_SPARK_WALLET_H

#include "primitives.h"
#include "../libspark/keys.h"
#include "../libspark/mint_transaction.h"
#include "../wallet/walletdb.h"

class CRecipient;
class CReserveKey;
class CCoinControl;

extern CChain chainActive;

const uint32_t BIP44_SPARK_INDEX = 0x6;

class CSparkWallet  {
public:
    CSparkWallet(const std::string& strWalletFile);

    // increment diversifier and generate address for that
    spark::Address generateNextAddress();
    spark::Address getDefaultAddress();
    // assign difersifier to the value from db
    void resetDiversifierFromDB(CWalletDB& walletdb);
    // assign diversifier in to to current value
    void updatetDiversifierInDB(CWalletDB& walletdb);

    // functions for key set generation
    spark::SpendKey generateSpendKey();
    spark::FullViewKey generateFullViewKey(const spark::SpendKey& spend_key);
    spark::IncomingViewKey generateIncomingViewKey(const spark::FullViewKey& full_view_key);

    // get map diversifier to Address
    std::unordered_map<int32_t, spark::Address> getAllAddresses();
    // get address for a diversifier
    spark::Address getAddress(const int32_t& i);
    // list spark mint, mint metadata in memory and in db should be the same at this moment, so get from memory
    std::vector<CSparkMintMeta> ListSparkMints(bool fUnusedOnly = false, bool fMatureOnly = false) const;
    // generate spark Coin from meta data
    spark::Coin getCoinFromMeta(const CSparkMintMeta& meta) const;

    // functions to get spark balance
    CAmount getFullBalance();
    CAmount getAvailableBalance();
    CAmount getUnconfirmedBalance();

    // function to be used for zap wallet
    void clearAllMints(CWalletDB& walletdb);
    // erase mint meta data from memory and from db
    void eraseMint(const uint256& hash, CWalletDB& walletdb);
    // add mint meta data to memory and to db
    void addOrUpdateMint(const CSparkMintMeta& mint, const uint256& lTagHash, CWalletDB& walletdb);
    CSparkMintMeta getMintMeta(const uint256& hash);

    void UpdateSpendStateFromMempool(const std::vector<GroupElement>& lTags, const uint256& txHash, bool fUpdateMint = true);
    void UpdateMintStateFromMempool(const std::vector<std::pair<spark::Coin, std::vector<unsigned char>>>& coins, const uint256& txHash);

    // get the vector of mint metadata for a single address
    std::vector<CSparkMintMeta> listAddressCoins(const int32_t& i, bool fUnusedOnly = false);


    // generate recipient data for mint transaction,
    static std::vector<CRecipient> CreateSparkMintRecipients(
            const std::vector<spark::MintedCoinData>& outputs,
            const std::vector<unsigned char>& serial_context,
            bool generate);

    bool CreateSparkMintTransactions(
            const std::vector<spark::MintedCoinData>&  outputs,
            std::vector<std::pair<CWalletTx,
            CAmount>>& wtxAndFee,
            CAmount& nAllFeeRet,
            std::list<CReserveKey>& reservekeys,
            int& nChangePosInOut,
            std::string& strFailReason,
            const CCoinControl *coinControl,
            bool autoMintAll = false);

    std::vector<CWalletTx> CreateSparkSpendTransaction(
            const std::vector<CRecipient>& recipients,
            const std::vector<spark::MintedCoinData>&  privateRecipients,
            CAmount &fee,
            const CCoinControl *coinControl = NULL);

    // Returns the list of pairs of coins and metadata for that coin,
    std::list<std::pair<spark::Coin, CSparkMintMeta>> GetAvailableSparkCoins(CWalletDB& walletdb, const CCoinControl *coinControl = NULL) const;

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
};


#endif //FIRO_SPARK_WALLET_H
