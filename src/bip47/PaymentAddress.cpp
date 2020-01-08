#include "PaymentAddress.h"
#include "PaymentCode.h"
#include "bip47_common.h"
#include "Bip47Util.h"



PaymentAddress::PaymentAddress()
{
    index = 0;

}
PaymentAddress::PaymentAddress(PaymentCode paymentCode_t)
{
    paymentCode = paymentCode_t;
    index = 0;
    
}

PaymentCode PaymentAddress::getPaymentCode() {
    return paymentCode;
}

void PaymentAddress::setPaymentCode(PaymentCode paymentCode_t) {
    paymentCode = paymentCode_t;
}
int PaymentAddress::getIndex() {
    return index;
}

void PaymentAddress::setIndex(int index_t) {
    index = index_t;
}

vector<unsigned char> PaymentAddress::getPrivKey() {
    return privKey;
}

void PaymentAddress::setIndexAndPrivKey(int index_t, vector<unsigned char> privKey_t) {
    index = index_t;
    privKey = privKey_t;
}

void PaymentAddress::setPrivKey(vector<unsigned char> privKey_t) {
    privKey = privKey_t;
}

CPubKey PaymentAddress::getSendECKey()
{
    return getSendECKey(getSecretPoint());
}

CKey PaymentAddress::getReceiveECKey()
{
    return getReceiveECKey(getSecretPoint());
}

CPubKey PaymentAddress::getReceiveECPubKey()
{
    return getReceiveECPubKey(getSecretPoint());
}

GroupElement PaymentAddress::get_sG()
{
    return get_sG(getSecretPoint());
}

SecretPoint PaymentAddress::getSharedSecret() {
    return sharedSecret();
}

Scalar PaymentAddress::getSecretPoint() {
    return secretPoint();
}


// GetECPoint from the public keys derived in PaymentCode 
GroupElement PaymentAddress::getECPoint(bool isMine) {
    
    
    
    vector<unsigned char> pubkeybytes;
    if(isMine)
    {
        pubkeybytes = pwalletMain->getBip47Account(0).getPaymentCode().addressAt(index).getPubKey();
    }
    else
    {
        pubkeybytes = paymentCode.addressAt(index).getPubKey();    
    }
    
    
    
    
    GroupElement ge;
    
    std::vector<unsigned char> serializedGe;
    std::copy(pubkeybytes.begin() + 1, pubkeybytes.end(), std::back_inserter(serializedGe));
    serializedGe.push_back(pubkeybytes[0] == 0x02 ? 0 : 1);
    serializedGe.push_back(0x0);
    ge.deserialize(&serializedGe[0]);
    

    return ge;
}



std::vector<unsigned char> PaymentAddress::hashSharedSecret() {

    std::vector<unsigned char> shardbytes = getSharedSecret().ECDHSecretAsBytes();
    LogPrintf("Hash Shared Secret: %s\n", HexStr(shardbytes));
    
    return shardbytes;
}

GroupElement PaymentAddress::get_sG(Scalar s) {

    GroupElement g = GroupElement("55066263022277343669578718895168534326250603453777594175500187360389116729240",
                             "32670510020758816978083085130507043184471273380659243275938904335757337482424");
    
    return g * s;
}

CPubKey PaymentAddress::getSendECKey(Scalar s)
{
    LogPrintf("getSendECKey:SecretPoint = %s\n", s.GetHex());
    
    GroupElement ecPoint = getECPoint();
    LogPrintf("getSendECKey:ecPoint = %s\n", ecPoint.GetHex());
    
    GroupElement sG = get_sG(s);
    LogPrintf("getSendECKey:sG = %s\n", sG.GetHex());
    GroupElement ecG = ecPoint + sG;
    LogPrintf("getSendECKey:ecG= %s\n", ecG.GetHex());
    LogPrintf("getSendECKey:buffersize required = %d\n", ecG.memoryRequired());

    vector<unsigned char> pubkey_vch  = ecG.getvch();
    pubkey_vch.pop_back();
    unsigned char header_char = pubkey_vch[pubkey_vch.size()-1] == 0 ? 0x02 : 0x03;
    pubkey_vch.pop_back();
    pubkey_vch.insert(pubkey_vch.begin(), header_char);
    
    LogPrintf("getSendECKey:pubkey_bytes = %s size = %d\n", HexStr(pubkey_vch), pubkey_vch.size());
    
    CPubKey pkey;
    pkey.Set(pubkey_vch.begin(), pubkey_vch.end());
    
    LogPrintf("Validate getSendECKey is %s\n", pkey.IsValid()? "true":"false");

    return pkey;
}

CPubKey PaymentAddress::getReceiveECPubKey(Scalar s)
{
    LogPrintf("getSendECKey:SecretPoint = %s\n", s.GetHex());
    
    GroupElement ecPoint = getECPoint(true);
    LogPrintf("getSendECKey:ecPoint = %s\n", ecPoint.GetHex());
    
    GroupElement sG = get_sG(s);
    LogPrintf("getSendECKey:sG = %s\n", sG.GetHex());
    GroupElement ecG = ecPoint + sG;
    LogPrintf("getSendECKey:ecG= %s\n", ecG.GetHex());
    LogPrintf("getSendECKey:buffersize required = %d\n", ecG.memoryRequired());

    vector<unsigned char> pubkey_vch  = ecG.getvch();
    pubkey_vch.pop_back();
    unsigned char header_char = pubkey_vch[pubkey_vch.size()-1] == 0 ? 0x02 : 0x03;
    pubkey_vch.pop_back();
    pubkey_vch.insert(pubkey_vch.begin(), header_char);
    
    LogPrintf("getSendECKey:pubkey_bytes = %s size = %d\n", HexStr(pubkey_vch), pubkey_vch.size());
    
    CPubKey pkey;
    pkey.Set(pubkey_vch.begin(), pubkey_vch.end());
    
    LogPrintf("Validate getSendECKey is %s\n", pkey.IsValid()? "true":"false");

    return pkey;
}

CKey PaymentAddress::getReceiveECKey(Scalar s)
{
    Scalar privKeyValue(privKey.data());
    Scalar newKeyS = privKeyValue + s;
    
    CKey pkey;
    
    vector<unsigned char> ppkeybytes = ParseHex(newKeyS.GetHex());
    pkey.Set(ppkeybytes.begin(), ppkeybytes.end(), true);
    LogPrintf( "getReceiveECKey validate key is %s\n", pkey.IsValid() ? "true":"false") ;
    return pkey;
}

SecretPoint PaymentAddress::sharedSecret()
{
    SecretPoint secP(privKey, paymentCode.addressAt(index).getPubKey());
    return secP;
}

secp_primitives::Scalar PaymentAddress::secretPoint()
{
    return secp_primitives::Scalar(hashSharedSecret().data());

}


/**
 * @selfTest
 * 
 * Glossary Of Definitions:
 * @incoming_address
 * 
 * b`  .pubkey : The incoming address is the Zcoin address with which the receiver expects to be paid.
 * 
 * @outgoing_address
 * 
 * B` : The outgoing address is the Zcoin address which the sender is going to send a transaction,
 *   with the expectation that the receiver will get this deposit.
 * 
 * 
 * This function is the one of UnitTest that can able to check the PaymentAddress generate incoming and outgoing addresses derived between alice and bob payment codes.
 * 
 * Calculate the New Public Key as    B` = B + Gs
 * Calcualte the New Private Key as   b` = b + s
 * 
 * B is pubkey derived from payment code of reciever (This shared from bob to Alice via payment code)
 * b is the private key dervived from payment code of reciever (This is only bob knows)
 * 
 * s is Shared Secret between alice and bob    calcaulted via Bob pubkey and Alice private or Bob private key and alice public key
 * 
 * G is the generator point of EC params
 * 
 * Now the checkable point is that
 * 
 * New found public key B` is verifiable from new found private key b`
 * 
 * key.VerifyPubKey(pubkey)
 * 
 * @Status false
 * @expect result true
 *  
 * */

bool PaymentAddress::SelfTest(CWallet* pwallet)
{
    
    PaymentCode toPcode("PM8TJK7t44xGE2DSbFGCk2wCypTzeq3L5i5r5iUGyNruaFLMCshtANUiBN1d9LCyQ9JrfDt3LFwRPSRkWPFBJAT7kdJgCaLDc3kQpQuwEVWxa6UmpR64");
    
    PaymentAddress payaddr = BIP47Util::getPaymentAddress(toPcode, 0, pwallet->getBip47Account(0).keyPrivAt(0));
    
    CExtPubKey extPubkey = pwallet->getBip47Account(0).keyAt(0);
    CExtKey extKey = pwallet->getBip47Account(0).keyPrivAt(0);
    CExtPubKey neutPubkey = extKey.Neuter();
    
    LogPrintf("extPubkey = %s\nneutPubkey = %s\n", extPubkey.pubkey.GetHash().GetHex(), neutPubkey.pubkey.GetHash().GetHex());
    
    
    CPubKey pubkey = payaddr.getReceiveECPubKey();
    CBitcoinAddress addr(pubkey.GetID());
    LogPrintf("Self Test Address get is %s\n", addr.ToString());
    
    CKey key = payaddr.getReceiveECKey();
    if (key.VerifyPubKey(pubkey))
        return true;
    return false;
    
}


