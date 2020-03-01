// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_COINSIGNER_H
#define ZCOIN_ELYSIUM_COINSIGNER_H

#include "ecdsasignature.h"
#include "key.h"
#include "pubkey.h"

#include <array>

namespace elysium {

class CoinSigner
{
public:
    CoinSigner(CKey const &priv);

protected:
    CKey key;

public:
    CPubKey GetPublicKey() const;
    ECDSASignature Sign(unsigned char const *start, unsigned char const *end);
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_WALLET_H