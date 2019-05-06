// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tinyformat.h>
#include "hdmint.h"

CHDMint::CHDMint()
{
    SetNull();
}

CHDMint::CHDMint(const uint32_t& nCount, const uint256& hashSeed, const uint256& hashSerial, const GroupElement& pubCoinValue)
{
    SetNull();
    this->nCount = nCount;
    this->hashSeed = hashSeed;
    this->hashSerial = hashSerial;
    this->pubCoinValue = pubCoinValue;
}

void CHDMint::SetNull()
{
    nCount = 0;
    hashSeed.SetNull();
    hashSerial.SetNull();
    txid.SetNull();
    nHeight = -1;
    nId = -1;
    denom = 5; // SIGMA_ERROR
    isUsed = false;
}

std::string CHDMint::ToString() const
{
    return strprintf(" HDMint:\n   count=%d\n   hashseed=%s\n   hashSerial=%s\n   hashpubCoinValue=%s\n   txid=%s\n   height=%d\n   id=%d\n   denom=%d\n   isUsed=%d\n",
    nCount, hashSeed.GetHex(), hashSerial.GetHex(), GetPubCoinHash().GetHex(), txid.GetHex(), nHeight, nId, denom, isUsed);
}
