#ifndef BIP47WALLET_H
#define BIP47WALLET_H

#include "bip47_common.h"
#include "wallet/wallet.h"

class Bip47Account;

class Bip47Wallet :public CWallet
{
public:
    Bip47Wallet();
    ~Bip47Wallet();

    


    Bip47Account getAccount(int i);
    void makeNotificationTransaction(String paymentCode);
    bool isNotificationTransaction();
    CBitcoinAddress getAddressOfReceived();

    void deriveAccount(vector<unsigned char> hd_seed);

private:
    vector<Bip47Account> mBip47Accounts;
};

#endif