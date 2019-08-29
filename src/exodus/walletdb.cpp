#include "walletdb.h"

namespace exodus {

// SigmaMintChainState Implementation.

SigmaMintChainState::SigmaMintChainState() : block(-1), group(0), index(0)
{
}

SigmaMintChainState::SigmaMintChainState(int block, MintGroupId group, MintGroupIndex index) :
    block(block),
    group(group),
    index(index)
{
}

bool SigmaMintChainState::operator==(const SigmaMintChainState& other) const
{
    return block == other.block && group == other.group && index == other.index;
}

bool SigmaMintChainState::operator!=(const SigmaMintChainState& other) const
{
    return !(*this == other);
}

void SigmaMintChainState::Clear()
{
    block = -1;
    group = 0;
    index = 0;
}

// SigmaEntry Implementation.

bool SigmaEntry::operator==(const SigmaEntry& other) const
{
    return privateKey == other.privateKey
        && spendTx == other.spendTx
        && propertyId == other.propertyId
        && denomination == other.denomination
        && chainState == other.chainState;
}

};
