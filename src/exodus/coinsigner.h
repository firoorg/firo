// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_COINSIGNER_H
#define ZCOIN_EXODUS_COINSIGNER_H

#include "hash.h"

namespace exodus {

class CoinSigner
{
public:
    CoinSigner(unsigned char const *ecdsaKey, size_t keySize);

protected:
    std::array<uint8_t, 32> key;
    CHashWriter hasher;

public:
    CoinSigner& Write(char const *pch, size_t size);
    std::array<uint8_t, 33> GetPublicKey() const;
    std::array<uint8_t, 64> GetSignature();
};

}

#endif // ZCOIN_EXODUS_WALLET_H