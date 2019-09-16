#ifndef BIP47WALLET_H
#define BIP47WALLET_H

#include "bip47_common.h"
#include "wallet/wallet.h"

class Bip47Wallet :public CWallet
{
public:
    Bip47Wallet();
    ~Bip47Wallet();
};

#endif