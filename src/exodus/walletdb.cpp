#include "walletdb.h"

namespace exodus {

bool SigmaEntry::operator==(const SigmaEntry& other) const
{
    return privateKey == other.privateKey
        && tx == other.tx
        && propertyId == other.propertyId
        && denomination == other.denomination
        && groupId == other.groupId
        && index == other.index
        && block == other.block;
}

};