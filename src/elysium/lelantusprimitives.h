// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_LELANTUSPRIMITIVES_H
#define ZCOIN_ELYSIUM_LELANTUSPRIMITIVES_H

#include "../liblelantus/coin.h"
#include "../uint256.h"

#include <cstdint>

namespace elysium {

typedef uint64_t LelantusAmount;
typedef uint32_t LelantusGroup;
typedef uint32_t LelantusIndex;

// Id of mint calculated from seed regardless of amount
class MintEntryId : public uint256 {
public:
    MintEntryId();
    MintEntryId(lelantus::PrivateCoin const &coin, uint160 const &seedId);
    MintEntryId(secp_primitives::Scalar const &serial, secp_primitives::Scalar const &randomness);
    MintEntryId(uint256 const &tag);
};

secp_primitives::GroupElement GetReduceCommitment(lelantus::PublicCoin const &pubCoin, LelantusAmount amount);

} // namespace elysium

#endif // ZCOIN_ELYSIUM_LELANTUSPRIMITIVES_H