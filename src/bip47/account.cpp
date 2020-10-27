
#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "util.h"

CBIP47Account::CBIP47Account(CExtKey &coinType, int identity) 
{
    accountId = identity;
    assert(coinType.Derive(prvkey,accountId | HARDENED_BIT));
    this->key = prvkey.Neuter();
    paymentCode = CPaymentCode(key.pubkey.begin(), (const unsigned char*)key.chaincode.begin());
}

CBIP47Account::CBIP47Account(std::string strPaymentCode) 
{
    accountId = 0;
    SetPaymentCodeString(strPaymentCode);
}

bool CBIP47Account::SetPaymentCodeString(std::string strPaymentCode)
{
    if (!CPaymentCode::createMasterPubKeyFromPaymentCode(strPaymentCode, this->key)) 
    {
        throw std::runtime_error("createMasterPubKeyFromPaymentCode return false while SetPaymentCodestd::string.\n");
    }

    paymentCode = CPaymentCode(strPaymentCode);
    return true;
}

bool CBIP47Account::isValid() const
{

    CBIP47Account testAccount(paymentCode.toString());
    std::vector<unsigned char> pcodePubkeybytes = testAccount.paymentCode.getPubKey();
    std::vector<unsigned char> acPubkeybytes(key.pubkey.begin(), key.pubkey.end());
    
    for(int i =0; i < pcodePubkeybytes.size(); i++) {
        if(pcodePubkeybytes[i] != acPubkeybytes[i])
        {
            return false;
        }
    }
    

    CExtPubKey pubkey;
    if (!CPaymentCode::createMasterPubKeyFromPaymentCode(paymentCode.toString(), pubkey)) 
    {
        LogPrintf("createMasterPubKeyFromPaymentCode Error in Function isValid.\n");
        return false;
    }

    if(pubkey.nDepth != key.nDepth) 
    {
        LogPrintf("nDepth invalid CBIP47Account");
        return false;
    }

    if(pubkey.chaincode.GetCheapHash() != key.chaincode.GetCheapHash())
    {
        LogPrintf("chaincode invalid CBIP47Account");
        return false;
    }
    for(int i =0; i< pubkey.pubkey.size(); i++) 
    {
        if(pubkey.pubkey[i] != key.pubkey[i])
        {
            return false;
        }
    }
    if(pubkey.pubkey.GetHash().GetCheapHash() != key.pubkey.GetHash().GetCheapHash())
    {
        LogPrintf("pubkey invalid CBIP47Account");
        return false;
    }

    return true;
}

std::string CBIP47Account::getStringPaymentCode() const
{
    return paymentCode.toString();
}

CBitcoinAddress CBIP47Account::getNotificationAddress() const
{
    CExtPubKey key0;
    key.Derive(key0, 0);
    CBitcoinAddress address(key0.pubkey.GetID());
    return address;
}

CExtPubKey CBIP47Account::getNotificationKey() 
{
    CExtPubKey result;
    if(key.Derive(result,0)) 
    {
        return result;
    }
    throw std::runtime_error("CBIP47Account getNotificationKey Problem");
}

CExtKey CBIP47Account::getNotificationPrivKey() 
{
       
    CExtKey result;
    
    prvkey.Derive(result,0);
    CExtPubKey extpubkey = getNotificationKey();
    if(result.key.VerifyPubKey(extpubkey.pubkey))
    {
        return result;
    }
    throw std::runtime_error("CBIP47Account Notification PrivKey Problem");
    
}

CPaymentCode const & CBIP47Account::getPaymentCode() const
{
    return paymentCode;
}

CBIP47ChannelAddress CBIP47Account::addressAt(int idx) const
{
    return CBIP47ChannelAddress(key, idx);
}

CExtPubKey CBIP47Account::keyAt(int idx) const
{
    CExtPubKey result;
    if(!key.Derive(result, idx))
    {
        throw runtime_error("keyAt error in CBIP47Account\n");
    }
    return result;
}

CExtKey CBIP47Account::keyPrivAt(int idx) const
{
    CExtKey result;
    if(!prvkey.Derive(result, idx))
    {
        throw runtime_error("keyPrivAt error in CBIP47Account\n");
    }
    
    return result;

}
