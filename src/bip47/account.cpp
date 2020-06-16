
#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "util.h"

Bip47Account::Bip47Account(CExtKey &coinType, int identity) {
    accountId = identity;
    assert(coinType.Derive(prvkey,accountId | HARDENED_BIT));
    LogPrintf("Get ExtPubkey From Extkey\n");
    this->key = prvkey.Neuter();
    LogPrintf("Get ExtPubkey From Extkey Done\n");
    paymentCode = PaymentCode(key.pubkey.begin(), (const unsigned char*)key.chaincode.begin());
}

Bip47Account::Bip47Account(std::string strPaymentCode) {
    accountId = 0;
    SetPaymentCodeString(strPaymentCode);
}

bool Bip47Account::SetPaymentCodeString(std::string strPaymentCode)
{
    if (!PaymentCode::createMasterPubKeyFromPaymentCode(strPaymentCode, this->key)) {
        throw std::runtime_error("createMasterPubKeyFromPaymentCode return false while SetPaymentCodestd::string.\n");
    }

    paymentCode = PaymentCode(strPaymentCode);
    return true;
}

bool Bip47Account::isValid()
{

    Bip47Account testAccount(paymentCode.toString());
    std::vector<unsigned char> pcodePubkeybytes = testAccount.paymentCode.getPubKey();
    std::vector<unsigned char> acPubkeybytes(key.pubkey.begin(), key.pubkey.end());


    if(pcodePubkeybytes.size() != acPubkeybytes.size()) {
        printf("mismatch size of pubkeys\n");
    }
    
    for(int i =0; i < pcodePubkeybytes.size(); i++) {
        if(pcodePubkeybytes[i] != acPubkeybytes[i])
        {
            printf("pcode pubkey bytes and ac pubkey bytes error 1\n");
            return false;
        }
    }
    

    CExtPubKey pubkey;
    if (!PaymentCode::createMasterPubKeyFromPaymentCode(paymentCode.toString(), pubkey)) {
        throw std::runtime_error("createMasterPubKeyFromPaymentCode Error in Function isValid.\n");
    }

    if(pubkey.nDepth != key.nDepth) {
        printf("key.nDepth= %d , pubkye.nDepth= %d\n", key.nDepth, pubkey.nDepth);
        std::runtime_error("nDepth invalid Bip47Account");
    }

    if(pubkey.chaincode.GetCheapHash() != key.chaincode.GetCheapHash())
    {
        printf("mismatch chaincode\n");
        std::runtime_error("chaincode invalid Bip47Account");
        return false;
    }
    for(int i =0; i< pubkey.pubkey.size(); i++) {
        if(pubkey.pubkey[i] != key.pubkey[i])
        {
            printf("pcode pubkey bytes and ac pubkey bytes error 2\n");
            return false;
        }
    }
    if(pubkey.pubkey.GetHash().GetCheapHash() != key.pubkey.GetHash().GetCheapHash())
    {
        printf("mismatch pubkey\n");
        std::runtime_error("pubkey invalid Bip47Account");
        return false;
    }

    return true;
}

std::string Bip47Account::getStringPaymentCode() 
{
    return paymentCode.toString();
}

CBitcoinAddress Bip47Account::getNotificationAddress() {
    CExtPubKey key0;
    key.Derive(key0 ,0);
    CBitcoinAddress address(key0.pubkey.GetID());
    return address;
}

CExtPubKey Bip47Account::getNotificationKey() {
    CExtPubKey result;
    if(key.Derive(result,0))
        return result;
    throw std::runtime_error("Bip47Account getNotificationKey Problem");
}

CExtKey Bip47Account::getNotificationPrivKey() {
       
    CExtKey result;
    
    prvkey.Derive(result,0);
    CExtPubKey extpubkey = getNotificationKey();
    if(result.key.VerifyPubKey(extpubkey.pubkey))
    {
        return result;
    }
    else
    {
        throw std::runtime_error("Bip47Account Notification PrivKey Problem");
    }
    
}

PaymentCode Bip47Account::getPaymentCode() {
    return paymentCode;
}

Bip47ChannelAddress Bip47Account::addressAt(int idx) {
    return Bip47ChannelAddress(key, idx);
}

CExtPubKey Bip47Account::keyAt(int idx) {
    CExtPubKey result;
    if(!key.Derive(result,idx))
    {
        LogPrintf("keyAt error in Bip47Account\n");
    }
    return result;
}

CExtKey Bip47Account::keyPrivAt(int idx)
{
    CExtKey result;
    if(!prvkey.Derive(result, idx))
    {
        LogPrintf("keyPrivAt error in Bip47Account\n");
    }
    
    return result;

}
