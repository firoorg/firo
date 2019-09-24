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
    Bip47Account(CBaseChainParams *parameters, CExtKey &coinType, int identity) {
        params = parameters;
        accountId = identity;
        CExtKey temp_key ;
        coinType.Derive(temp_key,accountId | HARDENED_BIT);
        key = temp_key.Neuter();
        paymentCode = PaymentCode(key.pubkey.begin(), key.chaincode.begin());
    }
    Bip47Account(CBaseChainParams *parameters, String strPaymentCode) {
        params = parameters;
        accountId = 0;
        PaymentCode::createMasterPubKeyFromPaymentCode(strPaymentCode,key);
        paymentCode = PaymentCode(strPaymentCode);
    }
    String getStringPaymentCode() {
        return paymentCode.toString();
    }

    CBitcoinAddress getNotificationAddress() {
        CExtPubKey key0;
        key.Derive(key0 ,0);
        CBitcoinAddress address(key0.pubkey.GetID());
        return address;
    }

    CExtPubKey getNotificationKey() {
        CExtPubKey result ;
        key.Derive(result,0);
        return result;
    }

    PaymentCode getPaymentCode() {
        return paymentCode;
    }

    Bip47ChannelAddress addressAt(int idx) {
        return Bip47ChannelAddress(params, key, idx);
    }

    CExtPubKey keyAt(int idx) {
        CExtPubKey result ;
        key.Derive(result,idx);
        return result;
    }

};

#endif