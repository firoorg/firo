#ifndef BIP47WALLET_H
#define BIP47WALLET_H

#include "bip47_common.h"
#include "wallet/wallet.h"
#include "Bip47PaymentChannel.h"
#include "Bip47Account.h"

class PaymentCode;

extern Bip47Wallet* pbip47WalletMain;

class Bip47Wallet :public CWallet
{
public:
    Bip47Wallet();
    ~Bip47Wallet(){};

    static bool initLoadBip47Wallet();

    Bip47Wallet(string strWalletFileIn, string coinName, string seedStr);
    Bip47Wallet(string strWalletFileIn, string coinName, CExtKey masterExtKey);
    


    std::string makeNotificationTransaction(std::string paymentCode);
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
    Bip47PaymentChannel getBip47PaymentChannelForOutgoingAddress(std::string strAddress);
    Bip47PaymentChannel getBip47PaymentChannelForPaymentCode(std::string paymentCode);
    CAmount getValueOfTransaction(CTransaction tx);
    CAmount getValueSentToMe(CTransaction tx);


    string getPaymentCode();
    string getNotifiactionAddress();




    void deriveAccount(vector<unsigned char> hd_seed);
    void deriveAccount(CExtKey masterKey);

    

private:
    vector<Bip47Account> mBip47Accounts;

    std::map<string, Bip47PaymentChannel> channels;

    std::string coinName;
};

#endif