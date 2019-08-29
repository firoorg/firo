#include "walletmodels.h"

namespace exodus {

// SigmaMintChainState Implementation.

SigmaMintChainState::SigmaMintChainState() noexcept : block(-1), group(0), index(0)
{
}

SigmaMintChainState::SigmaMintChainState(int block, MintGroupId group, MintGroupIndex index) noexcept :
    block(block),
    group(group),
    index(index)
{
}

bool SigmaMintChainState::operator==(const SigmaMintChainState& other) const noexcept
{
    return block == other.block && group == other.group && index == other.index;
}

bool SigmaMintChainState::operator!=(const SigmaMintChainState& other) const noexcept
{
    return !(*this == other);
}

void SigmaMintChainState::Clear() noexcept
{
    block = -1;
    group = 0;
    index = 0;
}

// SigmaMintId Implementation.

SigmaMintId::SigmaMintId() : property(0), denomination(0)
{
}

SigmaMintId::SigmaMintId(const SigmaMint& mint) :
    property(mint.property),
    denomination(mint.denomination),
    key(mint.key)
{
}

SigmaMintId::SigmaMintId(PropertyId property, DenominationId denomination, const SigmaPublicKey& key) :
    property(property),
    denomination(denomination),
    key(key)
{
}

bool SigmaMintId::operator==(const SigmaMintId& other) const
{
    return property == other.property && denomination == other.denomination && key == other.key;
}

bool SigmaMintId::operator!=(const SigmaMintId& other) const
{
    return !(*this == other);
}

// SigmaMint Implementation.

SigmaMint::SigmaMint() : property(0), denomination(0)
{
}

SigmaMint::SigmaMint(PropertyId property, DenominationId denomination) :
    property(property),
    denomination(denomination)
{
    key.Generate();
}

bool SigmaMint::operator==(const SigmaMint& other) const
{
    return property == other.property &&
           denomination == other.denomination &&
           chainState == other.chainState &&
           key == other.key &&
           spentTx == other.spentTx;
}

bool SigmaMint::operator!=(const SigmaMint& other) const
{
    return !(*this == other);
}

}
