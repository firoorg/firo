
#ifndef ZCOIN_BIP47ACCOUNT_H
#define ZCOIN_BIP47ACCOUNT_H
#include "bip47/paymentcode.h"
#include "key.h"
#include "pubkey.h"

namespace bip47 {

class CAccount
{
public:
    CAccount() { accountId = 0; }
    CAccount(CExtKey& coinType, int identity);
    CAccount(std::string const & strPaymentCode);

    bool SetPaymentCodeString(std::string const & strPaymentCode);
    std::string getStringPaymentCode() const;

    CBitcoinAddress getNotificationAddress() const;

    CExtPubKey getNotificationKey();
    CExtKey getNotificationPrivKey();

    CPaymentCode const & getPaymentCode() const;

    CChannelAddress addressAt(int idx) const;

    CExtPubKey keyAt(int idx) const;
    CExtKey keyPrivAt(int idx) const;
    bool isValid() const;

private:
    CExtKey prvkey;
    CExtPubKey key;
    int accountId;
    CPaymentCode paymentCode;
};

}

#endif // ZCOIN_BIP47ACCOUNT_H
