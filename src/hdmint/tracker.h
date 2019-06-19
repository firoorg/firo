// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_HDMINTTRACKER_H
#define ZCOIN_HDMINTTRACKER_H

#include "primitives/zerocoin.h"
#include <list>

class CHDMint;
class CHDMintWallet;

class CHDMintTracker
{
private:
    bool fInitialized;
    std::string strWalletFile;
    std::map<uint256, CMintMeta> mapSerialHashes;
    std::map<uint256, uint256> mapPendingSpends; //serialhash, txid of spend
    bool UpdateStatusInternal(const std::set<uint256>& setMempool, CMintMeta& mint);
public:
    CHDMintTracker(std::string strWalletFile);
    ~CHDMintTracker();
    void Add(const CHDMint& dMint, bool isNew = false, bool isArchived = false, CHDMintWallet* zerocoinWallet = NULL);
    void Add(const CSigmaEntry& zerocoin, bool isNew = false, bool isArchived = false);
    bool Archive(CMintMeta& meta);
    bool HasPubcoin(const GroupElement& pubcoin) const;
    bool HasPubcoinHash(const uint256& hashPubcoin) const;
    bool HasSerial(const Scalar& bnSerial) const;
    bool HasSerialHash(const uint256& hashSerial) const;
    bool HasMintTx(const uint256& txid);
    bool IsEmpty() const { return mapSerialHashes.empty(); }
    void Init();
    bool Get(const uint256& hashSerial, CMintMeta& mMeta);
    CMintMeta GetMetaFromPubcoin(const uint256& hashPubcoin);
    CAmount GetBalance(bool fConfirmedOnly, bool fUnconfirmedOnly) const;
    std::vector<uint256> GetSerialHashes();
    bool UpdateMints(std::set<uint256> serialHashes, bool fReset, bool fUpdateStatus, bool fStatus=false);
    std::list<CMintMeta> GetMints(bool fConfirmedOnly, bool fInactive = true) const;
    CAmount GetUnconfirmedBalance() const;
    bool MintMetaToZerocoinEntries(std::list <CSigmaEntry>& entries, std::list<CMintMeta> setMints) const;
    list<CSigmaEntry> MintsAsZerocoinEntries(bool fUnusedOnly = true, bool fMatureOnly = true);
    std::vector<CMintMeta> ListMints(bool fUnusedOnly = true, bool fMatureOnly = true, bool fUpdateStatus = true, bool fWrongSeed = false);
    void RemovePending(const uint256& txid);
    void SetPubcoinUsed(const uint256& hashPubcoin, const uint256& txid);
    void SetPubcoinNotUsed(const uint256& hashPubcoin);
    bool UnArchive(const uint256& hashPubcoin, bool isDeterministic);
    bool UpdateZerocoinEntry(const CSigmaEntry& zerocoin);
    bool UpdateState(const CMintMeta& meta);
    void SetMetaNonDeterministic();
    void Clear();
};

#endif //ZCOIN_HDMINTTRACKER_H