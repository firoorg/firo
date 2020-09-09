
#ifndef ZCOIN_BIP47ACCOUNT_H
#define ZCOIN_BIP47ACCOUNT_H
#include "bip47/paymentcode.h"
#include "bip47/utils.h"
#include "key.h"
#include "pubkey.h"

class CBIP47Account
{
public:
    CBIP47Account() { accountId = 0; }
    CBIP47Account(CExtKey& coinType, int identity);
    CBIP47Account(std::string strPaymentCode);

    bool SetPaymentCodeString(std::string strPaymentCode);
    std::string getStringPaymentCode() const;

    CBitcoinAddress getNotificationAddress();

    CExtPubKey getNotificationKey();
    CExtKey getNotificationPrivKey();

    CPaymentCode getPaymentCode();

    CBIP47ChannelAddress addressAt(int idx);

    CExtPubKey keyAt(int idx);
    CExtKey keyPrivAt(int idx);
    bool isValid();

private:
    CExtKey prvkey;
    CExtPubKey key;
    int accountId;
    CPaymentCode paymentCode;
};

#endif // ZCOIN_BIP47ACCOUNT_H
