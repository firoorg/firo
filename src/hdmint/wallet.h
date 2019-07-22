// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_HDMINTWALLET_H
#define ZCOIN_HDMINTWALLET_H

#include <map>
#include "libzerocoin/Zerocoin.h"
#include "hdmint/mintpool.h"
#include "uint256.h"
#include "primitives/zerocoin.h"
#include "wallet/wallet.h"
#include "tracker.h"

class CHDMint;

class CHDMintWallet
{
private:
    int32_t nCountNextUse;
    int32_t nCountNextGenerate;
    std::string strWalletFile;
    CMintPool mintPool;
    CHDMintTracker tracker;
    uint160 hashSeedMaster;

public:
    int static const COUNT_DEFAULT = 0;

    CHDMintWallet(const std::string& strWalletFile);

    bool SetupWallet(const uint160& hashSeedMaster, bool fResetCount=false);
    void SyncWithChain(bool fGenerateMintPool = true, boost::optional<std::list<std::pair<uint256, MintPoolEntry>>> listMints = boost::none);
    bool GenerateMint(const sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CHDMint& dMint, boost::optional<MintPoolEntry> mintPoolEntry = boost::none);
    bool LoadMintPoolFromDB();
    bool RegenerateMint(const CHDMint& dMint, CSigmaEntry& zerocoin);
    bool IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransaction& tx);
    bool TxOutToPublicCoin(const CTxOut& txout, sigma::PublicCoin& pubCoin, CValidationState& state);
    void RegenerateMintPoolEntry(const uint160& mintHashSeedMaster, CKeyID& seedId, const int32_t& nCount);
    void GenerateMintPool(int32_t nIndex = 0);
    bool SetMintSeedSeen(std::pair<uint256,MintPoolEntry> mintPoolEntryPair, const int& nHeight, const uint256& txid, const sigma::CoinDenomination& denom);
    bool SeedToZerocoin(const uint512& seedZerocoin, GroupElement& bnValue, sigma::PrivateCoin& coin);
    // Count updating functions
    int32_t GetCount();
    CHDMintTracker& GetTracker() { return tracker; }
    void ResetCount();
    void SetCount(int32_t nCount);
    void UpdateCountLocal();
    void UpdateCountDB();
    void UpdateCount();

private:
    CKeyID GetZerocoinSeedID(int32_t nCount);
    bool CreateZerocoinSeed(uint512& seedZerocoin, const int32_t& n, CKeyID& seedId, bool checkIndex=true);
};

#endif //ZCOIN_HDMINTWALLET_H
