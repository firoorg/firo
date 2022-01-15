// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_HDMINTWALLET_H
#define FIRO_HDMINTWALLET_H

#include <map>
#include "hdmint/mintpool.h"
#include "uint256.h"
#include "primitives/mint_spend.h"
#include "wallet/wallet.h"
#include "tracker.h"

class CHDMint;

static const unsigned int DEFAULT_MINTPOOL_SIZE = 20;
static const unsigned int MAX_MINTPOOL_SIZE = 200;

class CHDMintWallet
{
private:
    int32_t nCountNextUse;
    int32_t nCountNextGenerate;
    const std::string& strWalletFile;
    CMintPool mintPool;
    CHDMintTracker tracker;
    uint160 hashSeedMaster;

public:
    int static const COUNT_DEFAULT = 0;

    CHDMintWallet(const std::string& strWalletFile, bool resetCount=false);

    bool SetupWallet(const uint160& hashSeedMaster, bool fResetCount=false);
    void SyncWithChain(bool fGenerateMintPool = true, boost::optional<std::list<std::pair<uint256, MintPoolEntry>>> listMints = boost::none);
    bool GetHDMintFromMintPoolEntry(CWalletDB& walletdb, const sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CHDMint& dMint, MintPoolEntry& mintPoolEntry);
    bool GetLelantusHDMintFromMintPoolEntry(CWalletDB& walletdb, lelantus::PrivateCoin& coin, CHDMint& dMint, MintPoolEntry& mintPoolEntry);
    bool GenerateMint(CWalletDB& walletdb, const sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CHDMint& dMint, boost::optional<MintPoolEntry> mintPoolEntry = boost::none, bool fAllowUnsynced=false);
    bool GenerateLelantusMint(CWalletDB& walletdb, lelantus::PrivateCoin& coin, CHDMint& dMint, uint160& seedIdOut, boost::optional<MintPoolEntry> mintPoolEntry = boost::none, bool fAllowUnsynced=false);
    bool LoadMintPoolFromDB();
    bool RegenerateMint(CWalletDB& walletdb, const CHDMint& dMint, CSigmaEntry& sigma, bool forEstimation = false);
    bool RegenerateMint(CWalletDB& walletdb, const CHDMint& dMint, CLelantusEntry& sigma, bool forEstimation = false);
    bool GetSerialForPubcoin(const std::vector<std::pair<uint256, GroupElement>>& serialPubcoinPairs, const uint256& hashPubcoin, uint256& hashSerial);
    bool IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransactionRef & tx);
    bool IsLelantusSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransactionRef & tx);
    bool TxOutToPublicCoin(const CTxOut& txout, sigma::PublicCoin& pubCoin, CValidationState& state);
    std::pair<uint256,uint256> RegenerateMintPoolEntry(CWalletDB& walletdb, const uint160& mintHashSeedMaster, CKeyID& seedId, const int32_t& nCount);
    void GenerateMintPool(CWalletDB& walletdb, bool forceGenerate = false, int32_t nIndex = 0);
    bool SetMintSeedSeen(CWalletDB& walletdb, std::pair<uint256,MintPoolEntry> mintPoolEntryPair, int nHeight, const uint256& txid, const sigma::CoinDenomination& denom);
    bool SetLelantusMintSeedSeen(CWalletDB& walletdb, std::pair<uint256,MintPoolEntry> mintPoolEntryPair, int nHeight, const uint256& txid, uint64_t amount);
    bool SeedToMint(const uint512& mintSeed, GroupElement& bnValue, sigma::PrivateCoin& coin);
    bool SeedToLelantusMint(const uint512& mintSeed, lelantus::PrivateCoin& coin);

    // Count updating functions
    int32_t GetCount();
    CHDMintTracker& GetTracker() { return tracker; }
    void ResetCount(CWalletDB& walletdb);
    void SetCount(int32_t nCount);
    void UpdateCountLocal();
    void UpdateCountDB(CWalletDB& walletdb);
    void SetWalletTransactionBlock(CWalletTx &wtx, const CBlockIndex *blockIndex, const CBlock &block);

private:
    CKeyID GetMintSeedID(CWalletDB& walletdb, int32_t nCount);
    bool CreateMintSeed(CWalletDB& walletdb, uint512& mintSeed, const int32_t& n, CKeyID& seedId, bool nWriteChain = true);
};

#endif //FIRO_HDMINTWALLET_H
