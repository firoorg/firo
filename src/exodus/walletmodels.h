#ifndef ZCOIN_EXODUS_WALLETMODELS_H
#define ZCOIN_EXODUS_WALLETMODELS_H

#include "property.h"
#include "sigmaprimitives.h"

#include "../serialize.h"
#include "../uint256.h"
#include "../pubkey.h"

#include <functional>
#include <ostream>

#include <stddef.h>

namespace exodus {

class SigmaMintChainState
{
public:
    int block;
    SigmaMintGroup group;
    SigmaMintIndex index;

public:
    SigmaMintChainState() noexcept;
    SigmaMintChainState(int block, SigmaMintGroup group, SigmaMintIndex index) noexcept;

    bool operator==(const SigmaMintChainState& other) const noexcept;
    bool operator!=(const SigmaMintChainState& other) const noexcept;

    void Clear() noexcept;

    ADD_SERIALIZE_METHODS;

private:
    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        int32_t block = this->block;

        READWRITE(block);
        READWRITE(group);
        READWRITE(index);

        this->block = block;
    }
};

class SigmaMintId
{
public:
    PropertyId property;
    SigmaDenomination denomination;
    SigmaPublicKey pubKey;

public:
    SigmaMintId();
    SigmaMintId(PropertyId property, SigmaDenomination denomination, const SigmaPublicKey& key);

    bool operator==(const SigmaMintId& other) const;
    bool operator!=(const SigmaMintId& other) const;

    ADD_SERIALIZE_METHODS;

private:
    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(property);
        READWRITE(denomination);
        READWRITE(pubKey);
    }
};

class SigmaMint
{
public:
    SigmaMintId id;

    CKeyID seedId;
    uint160 serialId;

    SigmaMintChainState chainState;
    uint256 spendTx;

public:
    SigmaMint();
    SigmaMint(SigmaMintId const &id, CKeyID const &seedId, uint160 const &serialId);

    bool operator==(const SigmaMint& other) const;
    bool operator!=(const SigmaMint& other) const;

    ADD_SERIALIZE_METHODS;

private:
    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(id);
        READWRITE(seedId);
        READWRITE(serialId);
        READWRITE(chainState);
        READWRITE(spendTx);
    }
};

class SigmaSpend
{
public:
    SigmaMintId mint;
    SigmaMintGroup group;
    size_t groupSize;
    SigmaProof proof;

public:
    SigmaSpend(const SigmaMintId& mint, SigmaMintGroup group, size_t groupSize, const SigmaProof& proof);
};

} // namespace exodus

namespace std {

using namespace exodus;

// std::hash specialization.

template<>
struct hash<SigmaMintChainState>
{
    size_t operator()(const SigmaMintChainState& state) const
    {
        size_t h = 0;

        h ^= hash<int>()(state.block);
        h ^= hash<SigmaMintGroup>()(state.group);
        h ^= hash<SigmaMintIndex>()(state.index);

        return h;
    }
};

template<>
struct hash<SigmaMintId>
{
    size_t operator()(const SigmaMintId& id) const
    {
        size_t h = 0;

        h ^= hash<PropertyId>()(id.property);
        h ^= hash<SigmaDenomination>()(id.denomination);
        h ^= hash<SigmaPublicKey>()(id.pubKey);

        return h;
    }
};

template<>
struct hash<uint160> : hash<base_blob<160>>
{
};

template<>
struct hash<SigmaMint>
{
    size_t operator()(const SigmaMint& mint) const
    {
        size_t h = 0;

        h ^= hash<SigmaMintId>()(mint.id);
        h ^= hash<uint160>()(mint.seedId);
        h ^= hash<uint160>()(mint.serialId);
        h ^= hash<SigmaMintChainState>()(mint.chainState);
        h ^= hash<uint256>()(mint.spendTx);

        return h;
    }
};

// basic_ostream supports.

template<class Char, class Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const SigmaMintId& id)
{
    return os << "{property: " << id.property << ", denomination: " << id.denomination << ", pubKey: " << id.pubKey << '}';
}

template<class Char, class Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const SigmaMintChainState& state)
{
    return os << "{block: " << state.block << ", group: " << state.group << ", index: " << state.index << '}';
}

template<class Char, class Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const SigmaMint& mint)
{
    os << '{';
    os << "id: " << mint.id << ", ";
    os << "seedId: " << mint.seedId.GetHex() << ", ";
    os << "serialId: " << mint.serialId.GetHex() << ", ";
    os << "chainState: " << mint.chainState << ", ";
    os << "spentTx: " << mint.spendTx.GetHex();
    os << '}';

    return os;
}

} // namespace std

#endif // ZCOIN_EXODUS_WALLETMODELS_H
