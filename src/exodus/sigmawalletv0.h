// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_SIGMAWALLETV0_H
#define ZCOIN_EXODUS_SIGMAWALLETV0_H

#include "sigmawallet.h"

namespace exodus {

class SigmaWalletV0 : public SigmaWallet<SigmaPrivateKey>
{
public:
    SigmaWalletV0();

protected:
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed);
    unsigned GetChange() const;

public:
    using SigmaWallet::GeneratePrivateKey;
};

}

#endif // ZCOIN_EXODUS_SIGMAWALLETV0_H