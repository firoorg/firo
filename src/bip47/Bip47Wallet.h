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
    


    void makeNotificationTransaction(String paymentCode);
    CTransaction* getSignedNotificationTransaction(CWalletTx &sendRequest, string paymentCode);
    bool isNotificationTransaction();
    CBitcoinAddress getAddressOfReceived(CTransaction tx);
    CBitcoinAddress getAddressOfSent(CTransaction tx);
    PaymentCode getPaymentCodeInNotificationTransaction(CTransaction tx);
    bool savePaymentCode(PaymentCode paymentCode);
    Bip47Account getAccount(int i);
    CBitcoinAddress getAddressOfKey(CExtPubKey pkey);
    bool generateNewBip47IncomingAddress(std::string strAddress);
    Bip47PaymentChannel getBip47PaymentChannelForAddress(std::string strAddres);
    string getPaymentCodeForAddress(string address);


    void deriveAccount(vector<unsigned char> hd_seed);

    

private:
    vector<Bip47Account> mBip47Accounts;

    std::map<string, Bip47PaymentChannel> channels;

    std::string coinName;
};

#endif