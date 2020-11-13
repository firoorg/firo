
#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "util.h"
#include "bip47/utils.h"


namespace bip47 {

CAccount::CAccount(CExtKey &coinType, int identity) 
{
    accountId = identity;
    if(!coinType.Derive(prvkey, accountId | HARDENED_BIT)) {
        throw std::runtime_error("Cannot derive prvkey");
    }
    key = prvkey.Neuter();
    paymentCode = CPaymentCode(key.pubkey, key.chaincode);
}

CAccount::CAccount(std::string const & strPaymentCode)
{
    accountId = 0;
    SetPaymentCodeString(strPaymentCode);
}

bool CAccount::SetPaymentCodeString(std::string const & strPaymentCode)
{
    paymentCode = CPaymentCode(strPaymentCode);
    return true;
}

bool CAccount::isValid() const
{

    CAccount testAccount(paymentCode.toString());
    std::vector<unsigned char> pcodePubkeybytes(testAccount.paymentCode.getPubKey().begin(), testAccount.paymentCode.getPubKey().end());
    std::vector<unsigned char> acPubkeybytes(key.pubkey.begin(), key.pubkey.end());
    
    for(size_t i =0; i < pcodePubkeybytes.size(); i++) {
        if(pcodePubkeybytes[i] != acPubkeybytes[i])
        {
            return false;
        }
    }
    

    CExtPubKey pubkey = paymentCode.getChildPubKey0();

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
    for(size_t i =0; i< pubkey.pubkey.size(); i++)
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

