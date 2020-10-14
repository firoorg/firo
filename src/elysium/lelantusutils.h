// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../base58.h"
#include "../uint256.h"

namespace elysium {

uint256 PrepareSpendMetadata(CBitcoinAddress const &receiver, CAmount referenceAmount);

} // namespace elysium