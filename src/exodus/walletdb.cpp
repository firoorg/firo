#include "walletdb.h"

namespace exodus {

bool SigmaEntry::operator==(const SigmaEntry& other) const
{
    return privateKey == other.privateKey
        && isUsed == other.isUsed
        && propertyId == other.propertyId
        && denomination == other.denomination
        && groupId == other.groupId
        && index == other.index
        && block == other.block;
}

};