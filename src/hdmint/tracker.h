// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_HDMINTTRACKER_H
#define FIRO_HDMINTTRACKER_H

#include "primitives/mint_spend.h"
#include "hdmint/mintpool.h"
#include "wallet/walletdb.h"
#include <list>

class CHDMint;
class CHDMintWallet;

class CHDMintTracker
{
private:
    bool fInitialized;
    std::string strWalletFile;
    std::map<uint256, CLelantusMintMeta> mapLelantusSerialHashes;
    std::map<uint256, uint256> mapPendingSpends; //serialhash, txid of spend
    bool IsMempoolSpendOurs(const std::set<uint256>& setMempool, const uint256& hashSerial);
    bool UpdateLelantusMetaStatus(const std::set<uint256>& setMempool, CLelantusMintMeta& mint, bool fSpend=false);

    std::set<uint256> GetMempoolTxids();
public:
    CHDMintTracker(std::string strWalletFile);
    ~CHDMintTracker();
    void AddLelantus(CWalletDB& walletdb, const CHDMint& dMint, bool isNew = false, bool isArchived = false);
    bool Archive(CLelantusMintMeta& meta);
    bool HasPubcoinHash(const uint256& hashPubcoin, CWalletDB& walletdb) const;
    bool HasSerialHash(const uint256& hashSerial) const;
    bool HasLelantusSerialHash(const uint256& hashSerial) const;
    bool IsEmpty() const { return mapLelantusSerialHashes.empty(); }
    void Init();
    bool GetMetaFromSerial(const uint256& hashSerial, CLelantusMintMeta& mMeta);
    bool GetLelantusMetaFromPubcoin(const uint256& hashPubcoin, CLelantusMintMeta& mMeta);

    std::vector<uint256> GetSerialHashes();
    void UpdateFromBlock(const std::list<std::pair<uint256, MintPoolEntry>>& mintPoolEntries, const std::vector<CLelantusMintMeta>& updatedMeta);
    void UpdateMintStateFromBlock(const std::vector<std::pair<lelantus::PublicCoin, std::pair<uint64_t, uint256>>>& mints);
    void UpdateSpendStateFromBlock(const std::unordered_map<Scalar, int>& spentSerials);
    void UpdateLelantusMintStateFromMempool(const std::vector<GroupElement>& pubCoins, const std::vector<uint64_t>& amounts);
    void UpdateJoinSplitStateFromMempool(const std::vector<Scalar>& spentSerials);
    std::list<CLelantusEntry> MintsAsLelantusEntries(bool fUnusedOnly = true, bool fMatureOnly = true);
    std::vector<CLelantusMintMeta> ListLelantusMints(bool fUnusedOnly = true, bool fMatureOnly = true, bool fUpdateStatus = true, bool fLoad = false, bool fWrongSeed = false);
    void SetLelantusPubcoinUsed(const uint256& hashPubcoin, const uint256& txid);
    void SetLelantusPubcoinNotUsed(const uint256& hashPubcoin);
    bool UnArchive(const uint256& hashPubcoin, bool isDeterministic);
    bool UpdateState(const CLelantusMintMeta& meta);
    void Clear();
};

#endif //FIRO_HDMINTTRACKER_H
