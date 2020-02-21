#include "walletmodels.h"

namespace exodus {

// SigmaMintChainState Implementation.

SigmaMintChainState::SigmaMintChainState() noexcept : block(-1), group(0), index(0)
{
}

SigmaMintChainState::SigmaMintChainState(int block, SigmaMintGroup group, SigmaMintIndex index) noexcept :
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

// SigmaMint Implementation.

SigmaMint::SigmaMint() : property(0), denomination(0)
{
}

SigmaMint::SigmaMint(PropertyId property, SigmaDenomination denomination, CKeyID const &seedId, uint160 const &serialId) :
    property(property), denomination(denomination), seedId(seedId), serialId(serialId)
{
}

bool SigmaMint::operator==(const SigmaMint& other) const
{
    return property == other.property &&
           denomination == other.denomination &&
           seedId == other.seedId &&
           serialId == other.serialId &&
           createdTx == other.createdTx &&
           chainState == other.chainState &&
           spendTx == other.spendTx;
}

bool SigmaMint::operator!=(const SigmaMint& other) const
{
    return !(*this == other);
}

// SigmaMintId Implementation.
SigmaMintId::SigmaMintId() : property(0), denomination(0)
{
}

SigmaMintId::SigmaMintId(PropertyId property, SigmaDenomination denomination, const SigmaPublicKey& pubKey) :
    property(property),
    denomination(denomination),
    pubKey(pubKey)
{
}

bool SigmaMintId::operator==(const SigmaMintId& other) const
{
    return property == other.property && denomination == other.denomination && pubKey == other.pubKey;
}

bool SigmaMintId::operator!=(const SigmaMintId& other) const
{
    return !(*this == other);
}

// SigmaSpend Implementation.

SigmaSpend::SigmaSpend(const SigmaMintId& mint, SigmaMintGroup group, size_t groupSize, const SigmaProof& proof) :
    mint(mint),
    group(group),
    groupSize(groupSize),
    proof(proof)
{
}

} // namespace exodus
