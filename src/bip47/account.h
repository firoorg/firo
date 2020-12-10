#ifndef ZCOIN_BIP47ACCOUNT_H
#define ZCOIN_BIP47ACCOUNT_H

#include <map>

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

    typedef std::vector<CBitcoinAddress> AddrContT;

    AddrContT const & getMyUsedAddresses();
    AddrContT const & getMyNextAddresses();
    bool addressUsed(CBitcoinAddress const & address);

    CPaymentCode const & getMyPcode() const;
protected:
    size_t const accountNum;
    CExtKey privkey;
    CExtPubKey pubkey;
private:
    boost::optional<CPaymentCode> mutable myPcode;

    virtual AddrContT const & generateMyUsedAddresses() = 0;
    virtual AddrContT const & generateMyNextAddresses() = 0;
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

    virtual AddrContT const & generateMyUsedAddresses();
    virtual AddrContT const & generateMyNextAddresses();
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
    CAccountReceiver(CExtKey const & walletKey, size_t accountNum);

    CBitcoinAddress const & getMyNotificationAddress() const;

    bool acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, COutPoint const & outpoint, CPubKey const & outpoinPubkey);

    bool findTheirPcode(CPaymentCode const & pcode) const;
private:
    using ContT = std::vector<CPaymentChannel>;
    ContT mutable pchannels;
    boost::optional<CBitcoinAddress> mutable myNotificationAddress;

    AddrContT usedAddresses;
    AddrContT nextAddresses;

    virtual AddrContT const & generateMyUsedAddresses();
    virtual AddrContT const & generateMyNextAddresses();
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

    CAccountPtr createReceivingAccount();
    CAccountPtr provideSendingAccount(CPaymentCode const & theirPcode);
private:
    using ContT = std::map<size_t, CAccountPtr>;
    ContT accounts;
    CExtKey privkey;
};

}

#endif // ZCOIN_BIP47ACCOUNT_H
