#ifndef ZCOIN_BIP47ACCOUNT_H
#define ZCOIN_BIP47ACCOUNT_H

#include <map>

#include "bip47/paymentcode.h"
#include "bip47/paymentchannel.h"
#include "key.h"
#include "pubkey.h"

namespace bip47 {

class CWallet;
    
/**
 * A new account is created for each MY payment code.
 * Account masterkey is derived using the "masterkey_path/accountNum" path.
 * An account contains all THEIR payment codes sent to the account payment code.
 */    

class CAccountBase
{
public:
    CAccountBase(CExtKey const & walletKey, size_t accountNum);
    virtual ~CAccountBase() = default;

protected:
    size_t const accountNum;
    CExtKey privkey;
    CExtPubKey pubkey;
};

typedef std::shared_ptr<CAccountBase> CAccountPtr;

/******************************************************************************/

class CAccountSender : public CAccountBase
{
public:
    CAccountSender(CExtKey const & walletKey, size_t accountNum, CPaymentCode const & theirPcode);

    std::vector<unsigned char> getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret);

    CPaymentCode const & getTheirPcode() const;
private:
    CPaymentCode theirPcode;
    boost::optional<CPaymentChannel> mutable pchannel;
};

/******************************************************************************/

class CAccountReceiver  : public CAccountBase
{
public:
    CAccountReceiver(CExtKey const & walletKey, size_t accountNum);

    CPaymentCode const & getMyPcode() const;
    CBitcoinAddress const & getMyNotificationAddress() const;
    
    bool findTheirPcode(CPaymentCode const & pcode) const;
private:
    using ContT = std::vector<CPaymentChannel>;
    ContT pchannels;
    boost::optional<CPaymentCode> mutable myPcode;
    boost::optional<CBitcoinAddress> mutable myNotificationAddress;
};

/******************************************************************************/

/**
 * Contains and manages bip47 accounts. 
 * Wallet masterkey is derived using the m/47'/136' path.
 */    
    
class CWallet {
public:
    CWallet(std::vector<unsigned char> const & seedData);

    CAccountPtr createReceivingAccount();
    CAccountPtr provideSendingAccount(CPaymentCode const & theirPcode);
private:
    using ContT = std::map<size_t, CAccountPtr>;
    ContT accounts;
    CExtKey privkey;
};

}

#endif // ZCOIN_BIP47ACCOUNT_H
