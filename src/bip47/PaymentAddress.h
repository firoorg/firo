#ifndef PAYMENTADDRESS_H
#define PAYMENTADDRESS_H
#define NetworkParameters char*
#include "wallet/wallet.h"
#include "PaymentCode.h"

class PaymentAddress
{
private:
    /* data */
    int index ;
    vector<unsigned char> privKey;
    PaymentCode paymentCode;
    NetworkParameters networkParameters;
public:
    PaymentAddress(/* args */);
    PaymentAddress(PaymentCode paymentCode_t) ;
    PaymentAddress(NetworkParameters networkParameters, PaymentCode paymentCode, int index, vector<unsigned char> privKey) ;
    ~PaymentAddress();
    PaymentCode getPaymentCode() ;
    void setPaymentCode(PaymentCode paymentCode_t) ;
    int getIndex() ;
    void setIndex(int inedx_t);
    vector<unsigned char> getPrivKey();
    void setIndexAndPrivKey(int index, vector<unsigned char> privKey);
    void setPrivKey(vector<unsigned char> privKey);
};

#endif