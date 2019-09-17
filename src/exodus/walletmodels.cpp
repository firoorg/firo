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

SigmaMint::SigmaMint()
{
    SetNull();
}

SigmaMint::SigmaMint(
    const SigmaMintId &id,
    int32_t count,
    const CKeyID& seedId,
    const uint160& serialId)
    : id(id),
    count(count),
    seedId(seedId),
    serialId(serialId)
{
}

void SigmaMint::SetNull()
{
    id = SigmaMintId();

    count = 0;
    seedId.SetNull();
    serialId.SetNull();

    spendTx.SetNull();
    chainState = exodus::SigmaMintChainState();
}

bool SigmaMint::operator==(const SigmaMint &other) const {
    return id == other.id
        && count == other.count
        && seedId == other.seedId
        && serialId == other.serialId
        && spendTx == other.spendTx
        && chainState == other.chainState;
}

bool SigmaMint::operator!=(const SigmaMint &other) const {
    return !(*this == other);
}

std::string SigmaMint::ToString() const
{
    return strprintf(
        " SigmaMint:\n   count=%d\n   seedId=%s\n   serialId=%s\n   txid=%s\n   height=%d\n   id=%d\n   denom=%d\n   isUsed=%d\n",
        count, seedId.ToString(), serialId.GetHex(), spendTx.GetHex(),
        chainState.block, chainState.group, id.denomination, !spendTx.IsNull());
}

}
