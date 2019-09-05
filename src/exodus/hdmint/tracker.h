// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EXODUS_HDMINT_TRACKER_H
#define EXODUS_HDMINT_TRACKER_H

#include "../../hdmint/mintpool.h"

#include "hdmint.h"

namespace exodus
{

class HDMintWallet;

struct MintMeta
{
    uint32_t propertyId;
    uint8_t denomination;
    uint256 hashSerial;

    SigmaMintChainState chainState;

    uint256 spendTx;

    GroupElement const &GetPubCoinValue() const;
    void SetPubCoinValue(GroupElement const &other);
    uint256 const &GetPubCoinValueHash() const;
    bool IsUsed() { return !spendTx.IsNull(); }

private:
    GroupElement pubCoinValue;
    uint256 pubCoinValueHash;
};

class HDMintTracker
{
private:
    bool initialized;
    std::string walletFile;
    HDMintWallet *mintWallet;
    std::map<uint256, MintMeta> mapSerialHashes;

public:
    HDMintTracker(std::string walletFile, HDMintWallet *mintWallet);
    void Add(const HDMint& dMint, bool isNew = false);
    bool HasPubcoinHash(const uint256& hashPubcoin) const;
    bool HasSerialHash(const uint256& hashSerial) const;
    bool IsEmpty() const { return mapSerialHashes.empty(); }
    void Init();

    bool GetMetaFromSerial(const uint256& hashSerial, MintMeta& meta);
    bool GetMetaFromPubcoin(const uint256& hashPubcoin, MintMeta& meta);
    std::vector<uint256> GetSerialHashes();
    std::vector<MintMeta> GetMints(bool confirmedOnly, bool inactive) const;

    std::vector<SigmaMint> ListMints(bool unusedOnly = true, bool matureOnly = true);
    std::vector<MintMeta> ListMetas(bool unusedOnly, bool matureOnly, bool load);

    void ResetAllMintsChainState();
    void SetMintSpendTx(const uint256& hashPubcoin, const uint256& txid);
    void SetChainState(const uint256& pubcoinHash, const SigmaMintChainState& chainState);

    bool UpdateState(const MintMeta &meta);
    void Clear();
};

}; // namespace exodus

#endif // EXODUS_HDMINT_TRACKER_H
