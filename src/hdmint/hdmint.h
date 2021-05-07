// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_HDMINT_H
#define FIRO_HDMINT_H

#include "primitives/mint_spend.h"
#include "sigma.h"

/**
 * CHDMint object
 *
 * struct that is safe to store essential mint data, without holding any information that allows for actual spending
 * (ie. serial, randomness, private key)
 *
 * @return CHDMint object
 */
class CHDMint
{
private:
    int32_t nCount;
    CKeyID seedId;
    uint256 hashSerial;
    GroupElement pubCoinValue;
    uint256 txid;
    int nHeight;
    int nId;
    int64_t amount;
    bool isUsed;

public:
    CHDMint();
    CHDMint(const int32_t& nCount, const CKeyID& seedId, const uint256& hashSerial, const GroupElement& pubCoinValue);

    int64_t GetAmount() const {
        return amount;
    }
    int32_t GetCount() const { return nCount; }
    int GetHeight() const { return nHeight; }
    int GetId() const { return nId; }
    CKeyID GetSeedId() const { return seedId; }
    uint256 GetSerialHash() const { return hashSerial; }
    GroupElement GetPubcoinValue() const { return pubCoinValue; }
    uint256 GetPubCoinHash() const { return primitives::GetPubCoinValueHash(pubCoinValue); }
    uint256 GetTxHash() const { return txid; }
    bool IsUsed() const { return isUsed; }
    void SetAmount(int64_t amount) { this->amount = amount; }
    void SetHeight(int nHeight) { this->nHeight = nHeight; }
    void SetId(int nId) { this->nId = nId; }
    void SetNull();
    void SetTxHash(const uint256& txid) { this->txid = txid; }
    void SetUsed(const bool isUsed) { this->isUsed = isUsed; }
    void SetPubcoinValue(const GroupElement pubCoinValue) { this->pubCoinValue = pubCoinValue; }
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nCount);
        READWRITE(seedId);
        READWRITE(hashSerial);
        READWRITE(pubCoinValue);
        READWRITE(txid);
        READWRITE(nHeight);
        READWRITE(nId);
        READWRITE(amount);
        READWRITE(isUsed);
    };
};

#endif //FIRO_HDMINT_H

