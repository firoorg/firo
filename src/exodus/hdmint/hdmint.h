// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EXODUS_HDMINT_H
#define EXODUS_HDMINT_H

#include "../../primitives/zerocoin.h"

#include "../sigma.h"
#include "../walletmodels.h"

namespace exodus {

// struct that is safe to store essential mint data, without holding any information that allows for actual spending (serial, randomness, private key)
class HDMint
{
private:
    SigmaMintId id;

    int32_t count;
    CKeyID seedId;
    uint160 hashSerial;

    uint256 spendTx;
    SigmaMintChainState chainState;

public:
    HDMint();
    HDMint(
        SigmaMintId const &id,
        int32_t count,
        const CKeyID& seedId,
        const uint160& hashSerial);

    SigmaMintId const &GetId() const { return id; }

    int32_t GetCount() const { return count; }
    const CKeyID &GetSeedId() const { return seedId; }
    const uint160 &GetSerialHash() const { return hashSerial; }

    const uint256 &GetSpendTx() const { return spendTx; }
    const SigmaMintChainState &GetChainState() const { return chainState; }

    void SetNull();

    void SetMintId(const SigmaMintId &id) { this->id = id; }

    void SetSpendTx(const uint256& spendTx) { this->spendTx = spendTx; }
    void SetChainState(const SigmaMintChainState &chainState) { this->chainState = chainState; }

    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(id);
        READWRITE(count);
        READWRITE(seedId);
        READWRITE(hashSerial);
        READWRITE(spendTx);
        READWRITE(chainState);
    };
};

};

#endif // EXODUS_HDMINT_H

