#ifndef ZCOIN_BIP47ACCOUNT_H
#define ZCOIN_BIP47ACCOUNT_H
#include "bip47/common.h"
#include "bip47/paymentcode.h"
#include "key.h"
#include "pubkey.h"

class Bip47Account {
    private:
    CExtKey prvkey;
    CExtPubKey key;
    int accountId;
    PaymentCode paymentCode;

    public:
    Bip47Account() {accountId=0;}
    Bip47Account(CExtKey &coinType, int identity);
    Bip47Account(std::string strPaymentCode);

    bool SetPaymentCodeString(std::string strPaymentCode);
    std::string getStringPaymentCode();

    CBitcoinAddress getNotificationAddress();

    CExtPubKey getNotificationKey();
    CExtKey getNotificationPrivKey();

    PaymentCode getPaymentCode();

    Bip47ChannelAddress addressAt(int idx);

    CExtPubKey keyAt(int idx);
    CExtKey keyPrivAt(int idx);
    bool isValid();

};

#endif // ZCOIN_BIP47ACCOUNT_H
