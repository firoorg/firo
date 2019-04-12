// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <streams.h>
#include "primitives/zerocoin.h"
#include "hash.h"
#include "util.h"
#include "utilstrencodings.h"


bool CMintMeta::operator <(const CMintMeta& a) const
{
    return this->pubcoin < a.pubcoin;
}

uint256 GetSerialHash(const CBigNum& bnSerial)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnSerial;
    return Hash(ss.begin(), ss.end());
}

uint256 GetPubCoinHash(const CBigNum& bnValue)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnValue;
    return Hash(ss.begin(), ss.end());
}