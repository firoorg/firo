#include "Bip47Account.h"
#include "PaymentCode.h"

Bip47Account::Bip47Account(CBaseChainParams *parameters, CExtKey &coinType, int identity) {
    params = parameters;
    accountId = identity;
    CExtKey temp_key ;
    coinType.Derive(temp_key,accountId | HARDENED_BIT);
    key = temp_key.Neuter();
    paymentCode = PaymentCode(key.pubkey.begin(), key.chaincode.begin());
}
Bip47Account::Bip47Account(CBaseChainParams *parameters, String strPaymentCode) {
    params = parameters;
    accountId = 0;
    PaymentCode::createMasterPubKeyFromPaymentCode(strPaymentCode,key);
    paymentCode = PaymentCode(strPaymentCode);
}
String Bip47Account::getStringPaymentCode() {
    return paymentCode.toString();
}

CBitcoinAddress Bip47Account::getNotificationAddress() {
    CExtPubKey key0;
    key.Derive(key0 ,0);
    CBitcoinAddress address(key0.pubkey.GetID());
    return address;
}

CExtPubKey Bip47Account::getNotificationKey() {
    CExtPubKey result ;
    key.Derive(result,0);
    return result;
}

CExtKey Bip47Account::getNotificationPrivKey() {
    CExtKey result ;
    prvkey.Derive(result,0);
    return result;
}

PaymentCode Bip47Account::getPaymentCode() {
    return paymentCode;
}

Bip47ChannelAddress Bip47Account::addressAt(int idx) {
    return Bip47ChannelAddress(params, key, idx);
}

CExtPubKey Bip47Account::keyAt(int idx) {
    CExtPubKey result ;
    key.Derive(result,idx);
    return result;
}
