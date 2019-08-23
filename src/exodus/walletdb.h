#ifndef ZCOIN_EXODUS_WALLETDB_H
#define ZCOIN_EXODUS_WALLETDB_H

#include "../serialize.h"
#include "../wallet/walletdb.h"

#include "sigma.h"
#include "sigmadb.h"

#include <ostream>
#include <string>

namespace exodus {

struct SigmaMintChainState
{
    int block;
    MintGroupId group;
    MintGroupIndex index;

    SigmaMintChainState();
    SigmaMintChainState(int block, MintGroupId group, MintGroupIndex index);

    bool operator==(const SigmaMintChainState& other) const;
    bool operator!=(const SigmaMintChainState& other) const;

    void Clear();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        int32_t block = this->block;

        READWRITE(block);
        READWRITE(group);
        READWRITE(index);

        this->block = block;
    }
};

struct SigmaMintId
{
    SigmaMintId()
        : propertyId(0), denomination(0)
    {
    }

    SigmaMintId(const SigmaPublicKey& publicKey, uint32_t propertyId, uint8_t denomination)
        : propertyId(propertyId), denomination(denomination), publicKey(publicKey)
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(propertyId);
        READWRITE(denomination);
        READWRITE(publicKey);
    }

    uint32_t propertyId;
    uint8_t denomination;
    SigmaPublicKey publicKey;
};

struct SigmaEntry
{
    SigmaPrivateKey privateKey;

    uint256 tx;

    uint32_t propertyId;
    uint8_t denomination;

    SigmaMintChainState chainState;

    SigmaEntry() : propertyId(0), denomination(0)
    {
    }

    SigmaMintId GetId() const
    {
        return SigmaMintId(SigmaPublicKey(privateKey), propertyId, denomination);
    }

    bool operator==(const SigmaEntry& other) const;
    bool operator!=(const SigmaEntry& other) const
    {
        return !(*this == other);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(privateKey);

        READWRITE(tx);

        READWRITE(propertyId);
        READWRITE(denomination);
        READWRITE(chainState);
    }
};

}

namespace std {

template<class Char, class Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const exodus::SigmaMintChainState& state)
{
    return os << "{block: " << state.block << ", group: " << state.group << ", index: " << state.index << '}';
}

}

#endif // ZCOIN_EXODUS_WALLETDB_H
