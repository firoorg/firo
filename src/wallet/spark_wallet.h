// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_WALLET_H
#define FIRO_SPARK_WALLET_H

#include "../libspark/keys.h"
#include "../coin_containers.h"
#include "../primitives/mint_spend.h"
#include "walletdb.h"

class CSparkWallet  {
public:
    CSparkWallet(const std::string& strWalletFile);

    // increment diversifier and generate address for that
    spark::Address generateNextAddress();
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
    std::vector<CSparkMintMeta> ListSparkMints(bool fUnusedOnly = false, bool fMatureOnly = false);
    // generate spark Coin from meta data
    spark::Coin getCoinFromMeta(const CSparkMintMeta& meta);

    // functions to get spark balance
    CAmount getFullBalance();
    CAmount getAvailableBalance();
    CAmount getUnconfirmedBalance();

    // function to be used for zap wallet
    void clearAllMints(CWalletDB& walletdb);
    // erase mint meta data from memory and from db
    void eraseMint(const uint256& hash, CWalletDB& walletdb);
    // add mint meta data to memory and to db
    void addOrUpdate(const CSparkMintMeta& mint, CWalletDB& walletdb);
    CSparkMintMeta getMintMeta(const uint256& hash);

    // get the vector of mint metadata for a single address
    std::vector<CSparkMintMeta> listAddressCoins(const int32_t& i, bool fUnusedOnly = false);

private:
    // this is latest used diversifier
    int32_t lastDiversifier;

    // this is incoming view key, which is saved into db and is used to identify our coins
    spark::IncomingViewKey viewKey;

    // map diversifier to address.
    std::unordered_map<int32_t, spark::Address> addresses;

    // map nonceHash to coin meta
    std::unordered_map<uint256, CSparkMintMeta> coinMeta;
};


#endif //FIRO_SPARK_WALLET_H
