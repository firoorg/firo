#ifndef ZCOIN_EXODUS_WALLETMODELS_H
#define ZCOIN_EXODUS_WALLETMODELS_H

#include "property.h"
#include "sigma.h"
#include "sigmadb.h"

#include "../serialize.h"
#include "../uint256.h"

#include <functional>
#include <ostream>

#include <stddef.h>

namespace exodus {

// Declarations.

class SigmaMint;

// Definitions.

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
    explicit SigmaMintId(const SigmaMint& mint);
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
    PropertyId property;
    DenominationId denomination;
    SigmaMintChainState chainState;
    SigmaPrivateKey key;
    uint256 spentTx;

public:
    SigmaMint();
    SigmaMint(PropertyId property, DenominationId denomination);

    bool operator==(const SigmaMint& other) const;
    bool operator!=(const SigmaMint& other) const;

    ADD_SERIALIZE_METHODS;

private:
    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(property);
        READWRITE(denomination);
        READWRITE(chainState);
        READWRITE(key);
        READWRITE(spentTx);
    }
};

} // namespace exodus

namespace std {

using namespace exodus;

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
    os << "property: " << mint.property << ", ";
    os << "denomination: " << mint.denomination << ", ";
    os << "chainState: " << mint.chainState << ", ";
    os << "key: " << mint.key << ", ";
    os << "spentTx: " << mint.spentTx.GetHex();
    os << '}';

    return os;
}

} // namespace std

#endif // ZCOIN_EXODUS_WALLETMODELS_H
