// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_LELANTUSPRIMITIVES_H
#define ZCOIN_ELYSIUM_LELANTUSPRIMITIVES_H

#include "../liblelantus/coin.h"
#include "../uint256.h"

#include <cstdint>

namespace elysium {

typedef secp_primitives::GroupElement LelantusCoinId;

typedef uint64_t LelantusAmount;
typedef uint32_t LelantusGroup;
typedef uint32_t LelantusIndex;

class MintTag : public uint256 {
public:
    MintTag();
    MintTag(uint256 const &tag);

public:
    static MintTag CreateMintTag(
        lelantus::PrivateCoin const &coin,
        uint160 const &seedId,
        LelantusAmount amount);
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_LELANTUSPRIMITIVES_H