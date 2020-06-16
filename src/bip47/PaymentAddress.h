#ifndef ZCOIN_BIP47PAYMENTADDRESS_H
#define ZCOIN_BIP47PAYMENTADDRESS_H

#include "wallet/wallet.h"
#include "bip47/paymentcode.h"
#include "bip47/secretpoint.h"

class PaymentAddress
{
private:
    /* data */
    int index;
    vector<unsigned char> privKey;
    PaymentCode paymentCode;

public:
    PaymentAddress(/* args */);
    
    PaymentAddress(PaymentCode paymentCode_t);
    
    PaymentAddress(PaymentCode paymentCode_t, int index_t, vector<unsigned char> privKey_t): paymentCode(paymentCode_t), index(index_t), privKey(privKey_t) {};
    
    ~PaymentAddress() {};
    
    PaymentCode getPaymentCode();
    
    void setPaymentCode(PaymentCode paymentCode_t);
    
    int getIndex();
    
    void setIndex(int inedx_t);
    
    vector<unsigned char> getPrivKey();
    
    void setIndexAndPrivKey(int index, vector<unsigned char> privKey);
    
    void setPrivKey(vector<unsigned char> privKey);
    
    CPubKey getSendECKey();
    
    CPubKey getReceiveECPubKey();
    
    CKey getReceiveECKey();
    
    GroupElement get_sG();
    
    SecretPoint getSharedSecret();
    
    Scalar getSecretPoint();
    
    GroupElement getECPoint(bool isMine = false);
    
    std::vector<unsigned char> hashSharedSecret();
    
private:
    
    SecretPoint sharedSecret();
    
    Scalar secretPoint();
    
    GroupElement get_sG(Scalar s);
    
    CPubKey getSendECKey(Scalar s);

    CKey getReceiveECKey(Scalar s);
    
    CPubKey getReceiveECPubKey(Scalar s);

};
#endif // ZCOIN_BIP47PAYMENTADDRESS_H
