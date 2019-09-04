// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EXODUS_HDMINT_H
#define EXODUS_HDMINT_H

#include "../primitives/zerocoin.h"
#include "../sigma.h"
#include "../walletmodels.h"

namespace exodus {

//struct that is safe to store essential mint data, without holding any information that allows for actual spending (serial, randomness, private key)
class HDMint
{
private:
    uint32_t propertyId;
    uint8_t denomination;

    int32_t count;
    CKeyID seedId;
    uint256 hashSerial;
    GroupElement pubCoinValue;

    uint256 spendTx;
    SigmaMintChainState chainState;

public:
    HDMint();
    HDMint(
        uint32_t propertyId,
        uint8_t denomination,
        int32_t count,
        const CKeyID& seedId,
        const uint256& hashSerial,
        const GroupElement& pubCoinValue);

    uint32_t GetPropertyId() const { return propertyId; }
    uint8_t GetDenomination() const { return denomination; }
    int32_t GetCount() const { return count; }
    CKeyID GetSeedId() const { return seedId; }
    uint256 GetSerialHash() const { return hashSerial; }
    GroupElement GetPubCoinValue() const { return pubCoinValue; }
    uint256 GetPubCoinHash() const { return primitives::GetPubCoinValueHash(pubCoinValue); }

    uint256 GetSpendTx() const { return spendTx; }
    SigmaMintChainState GetChainState() const { return chainState; }

    void SetNull();

    void SetSpendTx(const uint256& spendTx) { this->spendTx = spendTx; }
    void SetPubcoinValue(GroupElement const &pubCoinValue) { this->pubCoinValue = pubCoinValue; }
    void SetChainState(exodus::SigmaMintChainState const &chainState) { this->chainState = chainState; }

    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(propertyId);
        READWRITE(denomination);
        READWRITE(count);
        READWRITE(seedId);
        READWRITE(hashSerial);
        READWRITE(pubCoinValue);
        READWRITE(spendTx);
        READWRITE(chainState);
    };
};

};

#endif // EXODUS_HDMINT_H

