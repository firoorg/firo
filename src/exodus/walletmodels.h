#ifndef ZCOIN_EXODUS_WALLETMODELS_H
#define ZCOIN_EXODUS_WALLETMODELS_H

#include "property.h"
#include "sigma.h"
#include "sigmadb.h"

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
    MintGroupId group;
    MintGroupIndex index;

public:
    SigmaMintChainState() noexcept;
    SigmaMintChainState(int block, MintGroupId group, MintGroupIndex index) noexcept;

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
    DenominationId denomination;
    SigmaPublicKey key;

public:
    SigmaMintId();
    SigmaMintId(PropertyId property, DenominationId denomination, const SigmaPublicKey& key);

    bool operator==(const SigmaMintId& other) const;
    bool operator!=(const SigmaMintId& other) const;

    ADD_SERIALIZE_METHODS;

private:
    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(property);
        READWRITE(denomination);
        READWRITE(key);
    }
};

class SigmaMint
{
public:
    SigmaMintId id;

    CKeyID seedId;
    uint160 serialId;

    uint256 spendTx;
    SigmaMintChainState chainState;

public:
    SigmaMint();
    SigmaMint(
        SigmaMintId const &id,
        const CKeyID& seedId,
        const uint160& hashSerial);

    void SetNull();

    bool operator==(const SigmaMint &) const;
    bool operator!=(const SigmaMint &) const;

    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(id);
        READWRITE(seedId);
        READWRITE(serialId);
        READWRITE(spendTx);
        READWRITE(chainState);
    };
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
        h ^= hash<MintGroupId>()(state.group);
        h ^= hash<MintGroupIndex>()(state.index);

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
        h ^= hash<DenominationId>()(id.denomination);
        h ^= hash<SigmaPublicKey>()(id.key);

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
        h ^= hash<uint160>()(mint.serialId);
        h ^= hash<uint256>()(mint.spendTx);
        h ^= hash<SigmaMintChainState>()(mint.chainState);

        return h;
    }
};

// basic_ostream supports.

template<class Char, class Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const SigmaMintId& id)
{
    return os << "{property: " << id.property << ", denomination: " << id.denomination << ", key: " << id.key << '}';
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
    os << "spentTx: " << mint.spendTx.GetHex() << ", ";
    os << "chainState: " << mint.chainState << ", ";
    os << '}';

    return os;
}

} // namespace std

#endif // ZCOIN_EXODUS_WALLETMODELS_H
