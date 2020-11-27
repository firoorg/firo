#ifndef ZCOIN_BIP47ACCOUNT_H
#define ZCOIN_BIP47ACCOUNT_H

#include <map>

#include "bip47/paymentcode.h"
#include "key.h"
#include "pubkey.h"

namespace bip47 {

class CWallet;
    
/**
 * A new account is created for each MY payment code.
 * Account masterkey is derived using the "masterkey_path/accountNum" path.
 * An account contains all THEIR payment codes sent to the account payment code.
 */    

class CAccount
{
public:
    CAccount(CExtKey const & walletKey, size_t accountNum);

    CPaymentCode const & getMyPcode() const;
    CBitcoinAddress const & getMyNotificationAddress() const;
    
    std::vector<CPaymentCode> const & getTheirPcodes() const;

private:
    size_t const accountNum;
    CExtKey privkey;
    CExtPubKey pubkey;
    boost::optional<CPaymentCode> mutable myPcode;
    boost::optional<CBitcoinAddress> mutable myNotificationAddress;
};
    

/**
 * Contains and manages bip47 accounts. 
 * Wallet masterkey is derived using the m/47'/136' path.
 */    
    
class CWallet {
public:
    CWallet(std::vector<unsigned char> const & seedData);
    
    CAccount const & getAccount(size_t accountNum);
private:
    using ContT=std::map<size_t, CAccount>;
    ContT accounts;
    CExtKey privkey;
};    



}

#endif // ZCOIN_BIP47ACCOUNT_H
