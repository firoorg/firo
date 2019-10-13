#ifndef BIP47ACCOUNT_H
#define BIP47ACCOUNT_H
#include "bip47_common.h"
#include "PaymentCode.h"

class Bip47Account {
    private:
    CExtKey prvkey;
    CExtPubKey key;
    int accountId;
    PaymentCode paymentCode;

    public:
    Bip47Account(CExtKey &coinType, int identity);
    Bip47Account(String strPaymentCode);
    String getStringPaymentCode();

    CBitcoinAddress getNotificationAddress();

    CExtPubKey getNotificationKey();
    CExtKey getNotificationPrivKey();

    PaymentCode getPaymentCode();

    Bip47ChannelAddress addressAt(int idx);

    CExtPubKey keyAt(int idx);
    bool isValid();

};

#endif