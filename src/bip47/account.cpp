
#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "util.h"

namespace bip47 {

CAccount::CAccount(CExtKey &coinType, int identity) 
{
    accountId = identity;
    assert(coinType.Derive(prvkey,accountId | HARDENED_BIT));
    this->key = prvkey.Neuter();
    paymentCode = CPaymentCode(key.pubkey.begin(), (const unsigned char*)key.chaincode.begin());
}

CAccount::CAccount(std::string strPaymentCode) 
{
    accountId = 0;
    SetPaymentCodeString(strPaymentCode);
}

bool CAccount::SetPaymentCodeString(std::string strPaymentCode)
{
    if (!CPaymentCode::createMasterPubKeyFromPaymentCode(strPaymentCode, this->key)) 
    {
        throw std::runtime_error("createMasterPubKeyFromPaymentCode return false while SetPaymentCodestd::string.\n");
    }

    paymentCode = CPaymentCode(strPaymentCode);
    return true;
}

bool CAccount::isValid() const
{

    CAccount testAccount(paymentCode.toString());
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
        LogPrintf("nDepth invalid CAccount");
        return false;
    }

    if(pubkey.chaincode.GetCheapHash() != key.chaincode.GetCheapHash())
    {
        LogPrintf("chaincode invalid CAccount");
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
        LogPrintf("pubkey invalid CAccount");
        return false;
    }

    return true;
}

std::string CAccount::getStringPaymentCode() const
{
    return paymentCode.toString();
}

CBitcoinAddress CAccount::getNotificationAddress() const
{
    CExtPubKey key0;
    key.Derive(key0, 0);
    CBitcoinAddress address(key0.pubkey.GetID());
    return address;
}

CExtPubKey CAccount::getNotificationKey() 
{
    CExtPubKey result;
    if(key.Derive(result,0)) 
    {
        return result;
    }
    throw std::runtime_error("CAccount getNotificationKey Problem");
}

CExtKey CAccount::getNotificationPrivKey() 
{
       
    CExtKey result;
    
    prvkey.Derive(result,0);
    CExtPubKey extpubkey = getNotificationKey();
    if(result.key.VerifyPubKey(extpubkey.pubkey))
    {
        return result;
    }
    throw std::runtime_error("CAccount Notification PrivKey Problem");
    
}

CPaymentCode const & CAccount::getPaymentCode() const
{
    return paymentCode;
}

CChannelAddress CAccount::addressAt(int idx) const
{
    return CChannelAddress(key, idx);
}

CExtPubKey CAccount::keyAt(int idx) const
{
    CExtPubKey result;
    if(!key.Derive(result, idx))
    {
        throw runtime_error("keyAt error in CAccount\n");
    }
    return result;
}

CExtKey CAccount::keyPrivAt(int idx) const
{
    CExtKey result;
    if(!prvkey.Derive(result, idx))
    {
        throw runtime_error("keyPrivAt error in CAccount\n");
    }
    
    return result;
}

}

