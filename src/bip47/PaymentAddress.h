#ifndef PAYMENTADDRESS_H
#define PAYMENTADDRESS_H
#define PaymentCode char*
#define NetworkParameters char*
class PaymentAddress
{
private:
    /* data */
    int index ;
    char* privKey ;
    PaymentCode paymentCode;
    NetworkParameters networkParameters;
public:
    PaymentAddress(/* args */);
    PaymentAddress(PaymentCode paymentCode_t) ;
    PaymentAddress(NetworkParameters networkParameters, PaymentCode paymentCode, int index, char* privKey) ;
    ~PaymentAddress();
    PaymentCode getPaymentCode() ;
    void setPaymentCode(PaymentCode paymentCode_t) ;
    int getIndex() ;
    void setIndex(int inedx_t);
    char* getPrivKey();
    void setIndexAndPrivKey(int index, char* privKey);
    void setPrivKey(char* privKey);
};

#endif