#ifndef BIP47ACCOUNT_H
#define BIP47ACCOUNT_H
#include "bip47_common.h"
#include "PaymentCode.h"
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
    Bip47Account(String strPaymentCode);

    bool SetPaymentCodeString(String strPaymentCode);
    String getStringPaymentCode();

    CBitcoinAddress getNotificationAddress();

    CExtPubKey getNotificationKey();
    CExtKey getNotificationPrivKey();

    PaymentCode getPaymentCode();

    Bip47ChannelAddress addressAt(int idx);

    CExtPubKey keyAt(int idx);
    CExtKey keyPrivAt(int idx);
    bool isValid();

};

#endif
