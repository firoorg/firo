#include "Bip47Account.h"
#include "PaymentCode.h"

Bip47Account::Bip47Account(CExtKey &coinType, int identity) {
    accountId = identity;
    CExtKey temp_key;
    assert(coinType.Derive(temp_key,accountId | HARDENED_BIT));
    this->key = temp_key.Neuter();
    paymentCode = PaymentCode(key.pubkey.begin(), (const unsigned char*)key.chaincode.begin());
}
Bip47Account::Bip47Account(String strPaymentCode) {
    accountId = 0;
    if (!PaymentCode::createMasterPubKeyFromPaymentCode(strPaymentCode,key)) {
        throw std::runtime_error("(CBaseChainParams *parameters, String strPaymentCode).\n");
    }

    paymentCode = PaymentCode(strPaymentCode);
}

bool Bip47Account::isValid()
{
    Bip47Account testAccount(paymentCode.toString());
    vector<unsigned char> pcodePubkeybytes = testAccount.paymentCode.getPubKey();
    vector<unsigned char> acPubkeybytes(key.pubkey.begin(), key.pubkey.end());


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
        throw std::runtime_error("(CBaseChainParams *parameters, String strPaymentCode).\n");
    }

    if(pubkey.nDepth != key.nDepth) {
        printf("key.nDepth= %d , pubkye.nDepth= %d\n", key.nDepth, pubkey.nDepth);
        std::runtime_error("nDepth invalid Bip47Account");
    }
    // if(pubkey.nChild != key.nChild) {
    //     printf("key.nChild= %d , pubkye.nChild= %d\n", key.nChild, pubkey.nChild);
    //     std::runtime_error("nChild invalid Bip47Account");
    // }
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
    // for(int i = 0; i < 4; i++) 
    // {
    //     if(pubkey.vchFingerprint[i] != key.vchFingerprint[i])
    //     std::runtime_error("vchFinger Print invalid Bip47Account");
    // }


    // unsigned char pubkeybytes[74], keybytes[74];
    // key.Encode(keybytes);
    // pubkey.Encode(pubkeybytes);
    // for(int i = 0; i < 74; i++)
    // {
    //     if (keybytes[i] != pubkeybytes[i])
    //     {
    //         return false;
    //     }
    // }

    return true;
}

String Bip47Account::getStringPaymentCode() 
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
    return Bip47ChannelAddress(key, idx);
}

CExtPubKey Bip47Account::keyAt(int idx) {
    CExtPubKey result ;
    key.Derive(result,idx);
    return result;
}