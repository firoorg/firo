// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "lelantusutils.h"

namespace elysium {

uint256 PrepareSpendMetadata(
    CBitcoinAddress const &receiver,
    CAmount referenceAmount)
{
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);

    // serialize payload
    uint160 keyId;
    AddressType type;
    if (!receiver.GetIndexKey(keyId, type)) {
        throw std::invalid_argument("Fail to get address key id.");
    }

    hasher.write(reinterpret_cast<char*>(keyId.begin()), keyId.size());

    referenceAmount = htole64(referenceAmount);
    hasher.write(reinterpret_cast<char*>(&referenceAmount), sizeof(referenceAmount));

    return hasher.GetHash();
}

} // namespace elysium