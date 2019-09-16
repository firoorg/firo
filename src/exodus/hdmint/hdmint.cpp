// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tinyformat.h>
#include "hdmint.h"

namespace exodus
{

HDMint::HDMint()
{
    SetNull();
}

HDMint::HDMint(
    const SigmaMintId &id,
    int32_t count,
    const CKeyID& seedId,
    const uint160& hashSerial)
    : id(id),
    count(count),
    seedId(seedId),
    hashSerial(hashSerial)
{
}

void HDMint::SetNull()
{
    id = SigmaMintId();

    count = 0;
    seedId.SetNull();
    hashSerial.SetNull();

    spendTx.SetNull();
    chainState = exodus::SigmaMintChainState();
}

std::string HDMint::ToString() const
{
    return strprintf(
        " HDMint:\n   count=%d\n   seedId=%s\n   hashSerial=%s\n   txid=%s\n   height=%d\n   id=%d\n   denom=%d\n   isUsed=%d\n",
        count, seedId.ToString(), hashSerial.GetHex(), spendTx.GetHex(),
        chainState.block, chainState.group, id.denomination, !spendTx.IsNull());
}

};