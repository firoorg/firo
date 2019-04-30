// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_HDMINT_H
#define ZCOIN_HDMINT_H

#include "primitives/zerocoin.h"

//struct that is safe to store essential mint data, without holding any information that allows for actual spending (serial, randomness, private key)
class CHDMint
{
private:
    uint32_t nCount;
    uint256 hashSeed;
    uint256 hashSerial;
    GroupElement pubCoinValue;
    uint256 txid;
    int nHeight;
    int nId;
    int denom;
    bool isUsed;

public:
    CHDMint();
    CHDMint(const uint32_t& nCount, const uint256& hashSeed, const uint256& hashSerial, const GroupElement& pubCoinValue);

    sigma::CoinDenominationV3 GetDenomination() const {
        sigma::CoinDenominationV3 value;
        IntegerToDenomination(denom, value);
        return value;
    }
    int GetDenominationValue() const {
        return denom;
    }
    uint32_t GetCount() const { return nCount; }
    int GetHeight() const { return nHeight; }
    int GetId() const { return nId; }
    uint256 GetSeedHash() const { return hashSeed; }
    uint256 GetSerialHash() const { return hashSerial; }
    GroupElement GetPubcoinValue() const { return pubCoinValue; }
    uint256 GetPubCoinHash() const { return GetPubCoinValueHash(pubCoinValue); }
    uint256 GetTxHash() const { return txid; }
    bool IsUsed() const { return isUsed; }
    void SetDenomination(const sigma::CoinDenominationV3 value) {
        int64_t denom;
        DenominationToInteger(value, denom);
        this->denom = denom;
    };
    void SetDenominationValue(const int& denom) { this->denom = denom; }
    void SetHeight(const int& nHeight) { this->nHeight = nHeight; }
    void SetId(const int& nId) { this->nId = nId; }
    void SetNull();
    void SetTxHash(const uint256& txid) { this->txid = txid; }
    void SetUsed(const bool isUsed) { this->isUsed = isUsed; }
    void SetPubcoinValue(const GroupElement pubCoinValue) { this->pubCoinValue = pubCoinValue; }
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(nCount);
        READWRITE(hashSeed);
        READWRITE(hashSerial);
        READWRITE(pubCoinValue);
        READWRITE(txid);
        READWRITE(nHeight);
        READWRITE(nId);
        READWRITE(denom);
        READWRITE(isUsed);
    };
};

#endif //ZCOIN_HDMINT_H