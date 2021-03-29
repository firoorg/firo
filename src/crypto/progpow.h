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

void safe_tohash256(std::string& input, ethash::hash256& hash);
int skewed_epoch_number(int height);
void header_hash(const CBlockHeader& header, uint256& hash);
void header_hash(const CBlockHeader& header, ethash::hash256& hash);
void progpow_hash(const CBlockHeader& header, uint256& hash, int height);

#endif // FIRO_PROGPOW_H
