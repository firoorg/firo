// Copyright (c) 2021 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_PROGPOW_H
#define FIRO_PROGPOW_H

#include <crypto/progpow/include/ethash/ethash.h>
#include <crypto/progpow/include/ethash/progpow.hpp>
#include <uint256.h>

class uint256;
class CBlockHeader;

void progpow_hash(const CBlockHeader& header, uint256& hash, int height);

#endif // FIRO_PROGPOW_H
