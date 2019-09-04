// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tinyformat.h>
#include "hdmint.h"

namespace exodus {

HDMint::HDMint()
{
    SetNull();
}

HDMint::HDMint(
    uint32_t propertyId,
    uint8_t denomination,
    int32_t count,
    const CKeyID& seedId,
    const uint256& hashSerial,
    const GroupElement& pubCoinValue)
    : propertyId(propertyId),
    denomination(denomination),
    count(count),
    seedId(seedId),
    hashSerial(hashSerial),
    pubCoinValue(pubCoinValue)
{
}

void HDMint::SetNull()
{
    propertyId = 0;
    denomination = 0;

    count = 0;
    seedId.SetNull();
    hashSerial.SetNull();
    pubCoinValue = secp_primitives::GroupElement();

    spendTx.SetNull();
    chainState = exodus::SigmaMintChainState();
}

std::string HDMint::ToString() const
{
    return strprintf(
        " HDMint:\n   count=%d\n   seedId=%s\n   hashSerial=%s\n   hashPubCoinValue=%s\n   txid=%s\n   height=%d\n   id=%d\n   denom=%d\n   isUsed=%d\n",
        count, seedId.ToString(), hashSerial.GetHex(), GetPubCoinHash().GetHex(), spendTx.GetHex(),
        chainState.block, chainState.group, denomination, !spendTx.IsNull());
}

};