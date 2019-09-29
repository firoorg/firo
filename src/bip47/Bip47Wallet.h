#ifndef BIP47WALLET_H
#define BIP47WALLET_H

#include "bip47_common.h"
#include "wallet/wallet.h"
#include "Bip47PaymentChannel.h"

class Bip47Account;
class PaymentCode;

class Bip47Wallet :public CWallet
{
public:
    Bip47Wallet();
    ~Bip47Wallet();

    Bip47Wallet(string strWalletFileIn, string coinName, string seedStr);
    


    Bip47Account getAccount(int i);
    void makeNotificationTransaction(String paymentCode);
    CTransaction* getSignedNotificationTransaction(CWalletTx &sendRequest, string paymentCode);
    bool isNotificationTransaction();
    CBitcoinAddress getAddressOfReceived(CTransaction tx);
    CBitcoinAddress getAddressOfSent(CTransaction tx);
    PaymentCode getPaymentCodeInNotificationTransaction(CTransaction tx);
    string getPaymentCodeForAddress(string address);


    void deriveAccount(vector<unsigned char> hd_seed);

    

private:
    vector<Bip47Account> mBip47Accounts;

    std::map<string, Bip47PaymentChannel> channels;

    std::string coinName;
};

#endif