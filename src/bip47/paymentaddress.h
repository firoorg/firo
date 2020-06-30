#ifndef ZCOIN_BIP47PAYMENTADDRESS_H
#define ZCOIN_BIP47PAYMENTADDRESS_H

#include "wallet/wallet.h"
#include "bip47/paymentcode.h"
#include "bip47/secretpoint.h"

class CPaymentAddress
{
    public:
        CPaymentAddress();
        CPaymentAddress(CPaymentCode paymentCode_t);
        CPaymentAddress(CPaymentCode paymentCode_t, int index_t, vector<unsigned char> privKey_t): index(index_t), privKey(privKey_t), paymentCode(paymentCode_t) {};
        ~CPaymentAddress() {};
        
        CPaymentCode getPaymentCode();
        void setPaymentCode(CPaymentCode paymentCode_t);
        int getIndex();
        void setIndex(int inedx_t);
        vector<unsigned char> getPrivKey();
        void setPrivKey(vector<unsigned char> privKey);
        void setIndexAndPrivKey(int index, vector<unsigned char> privKey);
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

        int index;
        vector<unsigned char> privKey;
        CPaymentCode paymentCode;

};
#endif // ZCOIN_BIP47PAYMENTADDRESS_H
