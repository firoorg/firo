#ifndef ZCOIN_BIP47ACCOUNT_H
#define ZCOIN_BIP47ACCOUNT_H

#include <map>

#include "bip47/defs.h"
#include "bip47/paymentcode.h"
#include "bip47/paymentchannel.h"
#include "key.h"
#include "pubkey.h"

namespace bip47 {

class CWallet;

class CAccountBase
{
public:
    CAccountBase(CExtKey const & walletKey, size_t accountNum); 
    virtual ~CAccountBase() = default;

    MyAddrContT const & getMyUsedAddresses();
    MyAddrContT const & getMyNextAddresses();
    bool addressUsed(CBitcoinAddress const & address);

    CPaymentCode const & getMyPcode() const;
protected:
    size_t const accountNum;
    CExtKey privkey;
    CExtPubKey pubkey;
private:
    boost::optional<CPaymentCode> mutable myPcode;

    virtual MyAddrContT const & generateMyUsedAddresses() = 0;
    virtual MyAddrContT const & generateMyNextAddresses() = 0;
    virtual bool markAddressUsed(CBitcoinAddress const &) = 0;
};

typedef std::shared_ptr<CAccountBase> CAccountPtr;

/******************************************************************************/

/**
 * A sender account is created when the wallet pays to a 'their' payment code.
 * It has just one payment channel which handles payments to their account. 
 */

class CAccountSender : public CAccountBase
{
public:
    CAccountSender(CExtKey const & walletKey, size_t accountNum, CPaymentCode const & theirPcode);

    CPaymentChannel & getPaymentChannel();
    std::vector<unsigned char> getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret);

    CPaymentCode const & getTheirPcode() const;
private:
    CPaymentCode theirPcode;
    boost::optional<CPaymentChannel> mutable pchannel;
    MyAddrContT nextAddresses;

    virtual MyAddrContT const & generateMyUsedAddresses();
    virtual MyAddrContT const & generateMyNextAddresses();
    virtual bool markAddressUsed(CBitcoinAddress const &);
};

/******************************************************************************/

/**
 * A receiver account is created every time we publish a payment code.
 * Every time a notification tx is received, a new payment channel for this tx's
 * payment code is created.
 */
class CAccountReceiver : public CAccountBase
{
public:
    CAccountReceiver(CExtKey const & walletKey, size_t accountNum, std::string const & label);

    CBitcoinAddress const & getMyNotificationAddress() const;

    bool acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, COutPoint const & outpoint, CPubKey const & outpoinPubkey);

    bool findTheirPcode(CPaymentCode const & pcode) const;

    std::string const & getLabel() const;
private:
    using PChannelContT = std::vector<CPaymentChannel>;
    PChannelContT mutable pchannels;
    boost::optional<CBitcoinAddress> mutable myNotificationAddress;

    MyAddrContT usedAddresses;
    MyAddrContT nextAddresses;
    std::string label;

    virtual MyAddrContT const & generateMyUsedAddresses();
    virtual MyAddrContT const & generateMyNextAddresses();
    virtual bool markAddressUsed(CBitcoinAddress const &);
};

/******************************************************************************/

/**
 * Contains and manages bip47 accounts. 
 * Wallet masterkey is derived using the m/47'/136' path.
 */    
    
class CWallet {
public:
    CWallet(std::vector<unsigned char> const & seedData);
    CWallet(uint256 const & seedData);

    CAccountReceiver & createReceivingAccount(std::string const & label);
    CAccountSender & provideSendingAccount(CPaymentCode const & theirPcode);

    template<class E>
    void enumerateAccounts(E e);
private:
    using ContT = std::map<size_t, CAccountPtr>;
    ContT accounts;
    CExtKey privkey;
};

template<class UnaryFunction>
void CWallet::enumerateAccounts(UnaryFunction e)
{
    for(ContT::value_type const & val : accounts) {
        e(val.second);
    }
}


}

#endif // ZCOIN_BIP47ACCOUNT_H
