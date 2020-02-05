// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigmawallet.h"

#include "walletmodels.h"

#include "../uint256.h"

#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"

#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <boost/optional.hpp>

#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

namespace exodus {

MintPoolEntry::MintPoolEntry()
{
}

MintPoolEntry::MintPoolEntry(SigmaPublicKey const &key, CKeyID const &seedId, uint32_t index)
    : key(key), seedId(seedId), index(index)
{
}

bool MintPoolEntry::operator==(MintPoolEntry const &another) const
{
    return key == another.key &&
        seedId == another.seedId &&
        index == another.index;
}

bool MintPoolEntry::operator!=(MintPoolEntry const &another) const
{
    return !(*this == another);
}


} // exodus
