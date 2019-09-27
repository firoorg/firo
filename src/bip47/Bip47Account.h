#ifndef BIP47ACCOUNT_H
#define BIP47ACCOUNT_H
#include "bip47_common.h"
#include "PaymentCode.h"

class Bip47Account {
    private:
    CBaseChainParams *params ;
    CExtPubKey key;
    int accountId;
    PaymentCode paymentCode;

    public:
    Bip47Account(CBaseChainParams *parameters, CExtKey &coinType, int identity);
    Bip47Account(CBaseChainParams *parameters, String strPaymentCode);
    String getStringPaymentCode();

    CBitcoinAddress getNotificationAddress();

    CExtPubKey getNotificationKey();

    PaymentCode getPaymentCode();

    Bip47ChannelAddress addressAt(int idx);

    CExtPubKey keyAt(int idx);

};

#endif