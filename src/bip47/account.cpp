
#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "util.h"
#include "bip47/utils.h"
#include "wallet/wallet.h"


namespace bip47 {

CAccount::CAccount(CExtKey const & walletKey, size_t accountNum)
:accountNum(accountNum)
{
    walletKey.Derive(privkey, uint32_t(accountNum) | BIP32_HARDENED_KEY_LIMIT);
    pubkey = privkey.Neuter();
}

CPaymentCode const & CAccount::getMyPcode() const {
    if(!myPcode) {
        myPcode.emplace(pubkey.pubkey, pubkey.chaincode);
    }
    return *myPcode;
}

CBitcoinAddress const & CAccount::getMyNotificationAddress() const {
    if(!myNotificationAddress) {
        myNotificationAddress.emplace(getMyPcode().getNotificationAddress());
    }
    return *myNotificationAddress;
}

std::vector<CPaymentCode> const & CAccount::getTheirPcodes() const {
    return std::vector<CPaymentCode>();
}

/******************************************************************************/

CWallet::CWallet(std::vector<unsigned char> const & seedData) {
    CExtKey seedKey;
    seedKey.SetMaster(seedData.data(), seedData.size());
    privkey = utils::derive(seedKey, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});
}

CAccount const & CWallet::getAccount(size_t accountNum) {
    ContT::iterator iter = accounts.find(accountNum);
    if(iter == accounts.end()) {
        return accounts.emplace(accountNum, CAccount(privkey, accountNum)).first->second;
    }
    return iter->second;
}

}
