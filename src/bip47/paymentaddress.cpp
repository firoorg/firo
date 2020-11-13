#include "bip47/paymentaddress.h"
#include "bip47/paymentcode.h"
#include "bip47/utils.h"

namespace bip47 {

CPaymentAddress::CPaymentAddress()
{
    index = 0;

}
CPaymentAddress::CPaymentAddress(CPaymentCode paymentCode_t)
{
    paymentCode = paymentCode_t;
    index = 0;
    
}

CPaymentCode CPaymentAddress::getPaymentCode() {
    return paymentCode;
}

void CPaymentAddress::setPaymentCode(CPaymentCode paymentCode_t) {
    paymentCode = paymentCode_t;
}
int CPaymentAddress::getIndex() {
    return index;
}

void CPaymentAddress::setIndex(int index_t) {
    index = index_t;
}

vector<unsigned char> CPaymentAddress::getPrivKey() {
    return privKey;
}

void CPaymentAddress::setIndexAndPrivKey(int index_t, vector<unsigned char> privKey_t) {
    index = index_t;
    privKey = privKey_t;
}

void CPaymentAddress::setPrivKey(vector<unsigned char> privKey_t) {
    privKey = privKey_t;
}

CPubKey CPaymentAddress::getSendECKey()
{
    return getSendECKey(getSecretPoint());
}

CKey CPaymentAddress::getReceiveECKey()
{
    return getReceiveECKey(getSecretPoint());
}

CPubKey CPaymentAddress::getReceiveECPubKey()
{
    return getReceiveECPubKey(getSecretPoint());
}

GroupElement CPaymentAddress::get_sG()
{
    return get_sG(getSecretPoint());
}

CSecretPoint CPaymentAddress::getSharedSecret() {
    return sharedSecret();
}

Scalar CPaymentAddress::getSecretPoint() {
    return secretPoint();
}


// GetECPoint from the public keys derived in CPaymentCode 
GroupElement CPaymentAddress::getECPoint(bool isMine)
{
    CExtPubKey pubkey;
    if(isMine) {
        pubkey = pwalletMain->getBIP47Account(0).getPaymentCode().getNthPubkey(index);
    } else {
        pubkey = paymentCode.getNthPubkey(index);
    }
    GroupElement ge;
    std::vector<unsigned char> serializedGe;
    std::copy(pubkey.pubkey.begin() + 1, pubkey.pubkey.end(), std::back_inserter(serializedGe));
    serializedGe.push_back(pubkey.pubkey[0] == 0x02 ? 0 : 1);
    serializedGe.push_back(0x0);
    ge.deserialize(&serializedGe[0]);

    return ge;
}


std::vector<unsigned char> CPaymentAddress::hashSharedSecret() {

    std::vector<unsigned char> shardbytes = getSharedSecret().getEcdhSecret();
    
    return shardbytes;
}

GroupElement CPaymentAddress::get_sG(Scalar s) {

    GroupElement g = GroupElement("55066263022277343669578718895168534326250603453777594175500187360389116729240",
                             "32670510020758816978083085130507043184471273380659243275938904335757337482424");
    
    return g * s;
}

CPubKey CPaymentAddress::getSendECKey(Scalar s)
{
    GroupElement ecPoint = getECPoint();
    
    GroupElement sG = get_sG(s);
    GroupElement ecG = ecPoint + sG;

    vector<unsigned char> pubkey_vch  = ecG.getvch();
    pubkey_vch.pop_back();
    unsigned char header_char = pubkey_vch[pubkey_vch.size()-1] == 0 ? 0x02 : 0x03;
    pubkey_vch.pop_back();
    pubkey_vch.insert(pubkey_vch.begin(), header_char);
    
    CPubKey pkey;
    pkey.Set(pubkey_vch.begin(), pubkey_vch.end());
    
    return pkey;
}

CPubKey CPaymentAddress::getReceiveECPubKey(Scalar s)
{    
    GroupElement ecPoint = getECPoint(true);
    
    GroupElement sG = get_sG(s);
    GroupElement ecG = ecPoint + sG;

    vector<unsigned char> pubkey_vch  = ecG.getvch();
    pubkey_vch.pop_back();
    unsigned char header_char = pubkey_vch[pubkey_vch.size()-1] == 0 ? 0x02 : 0x03;
    pubkey_vch.pop_back();
    pubkey_vch.insert(pubkey_vch.begin(), header_char);
        
    CPubKey pkey;
    pkey.Set(pubkey_vch.begin(), pubkey_vch.end());
    
    return pkey;
}

CKey CPaymentAddress::getReceiveECKey(Scalar s)
{
    Scalar privKeyValue(privKey.data());
    Scalar newKeyS = privKeyValue + s;
    
    CKey pkey;
    
    vector<unsigned char> ppkeybytes = ParseHex(newKeyS.GetHex());
    pkey.Set(ppkeybytes.begin(), ppkeybytes.end(), true);
    return pkey;
}

CSecretPoint CPaymentAddress::sharedSecret()
{
    CKey privkey; privkey.Set(privKey.begin(), privKey.end(), false);
    CSecretPoint secP(privkey, paymentCode.getNthPubkey(index).pubkey);
    return secP;
}

secp_primitives::Scalar CPaymentAddress::secretPoint()
{
    return secp_primitives::Scalar(hashSharedSecret().data());

}

}
