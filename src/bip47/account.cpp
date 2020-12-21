
#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "util.h"
#include "bip47/utils.h"
#include "wallet/wallet.h"


namespace bip47 {

CAccountBase::CAccountBase(CExtKey const & walletKey, size_t accountNum)
:accountNum(accountNum)
{
    walletKey.Derive(privkey, uint32_t(accountNum) | BIP32_HARDENED_KEY_LIMIT);
    pubkey = privkey.Neuter();
}

MyAddrContT const & CAccountBase::getMyUsedAddresses()
{
    return generateMyUsedAddresses();
}

MyAddrContT const & CAccountBase::getMyNextAddresses()
{
    return generateMyNextAddresses();
}

bool CAccountBase::addressUsed(CBitcoinAddress const & address)
{
    return markAddressUsed(address);
}

CPaymentCode const & CAccountBase::getMyPcode() const
{
    if(!myPcode) {
        myPcode.emplace(pubkey.pubkey, pubkey.chaincode);
    }
    return *myPcode;
}

/******************************************************************************/

CAccountSender::CAccountSender(CExtKey const & walletKey, size_t accountNum, CPaymentCode const & theirPcode)
: CAccountBase(walletKey, accountNum), theirPcode(theirPcode)
{
}

CPaymentChannel & CAccountSender::getPaymentChannel() {
    if(!pchannel)
        pchannel.emplace(theirPcode, privkey, CPaymentChannel::Side::sender);
    return *pchannel;
}

std::vector<unsigned char> CAccountSender::getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret)
{
    return getPaymentChannel().getMaskedPayload(outpoint, outpointSecret);
}

CPaymentCode const & CAccountSender::getTheirPcode() const
{
    return theirPcode;
}

MyAddrContT const & CAccountSender::generateMyUsedAddresses()
{
    return getPaymentChannel().generateMyUsedAddresses();
}

MyAddrContT const & CAccountSender::generateMyNextAddresses()
{
    return getPaymentChannel().generateMyNextAddresses();
}

bool CAccountSender::markAddressUsed(CBitcoinAddress const & address)
{
    return getPaymentChannel().markAddressUsed(address);
}

/******************************************************************************/

CAccountReceiver::CAccountReceiver(CExtKey const & walletKey, size_t accountNum, std::string const & label)
: CAccountBase(walletKey, accountNum), label(label)
{}

CBitcoinAddress const & CAccountReceiver::getMyNotificationAddress() const
{
    if(!myNotificationAddress) {
        myNotificationAddress.emplace(getMyPcode().getNotificationAddress());
    }
    return *myNotificationAddress;
}

namespace {
    struct CompByPcode {
        CompByPcode(CPaymentCode const & comp): comp(comp){};
        bool operator()(CPaymentChannel const & other) const {return other.getTheirPcode() == comp;};
        CPaymentCode const & comp;
    };
}

bool CAccountReceiver::findTheirPcode(CPaymentCode const & pcode) const
{
    return std::find_if(pchannels.begin(), pchannels.end(), CompByPcode(pcode)) != pchannels.end();
}

std::string const & CAccountReceiver::getLabel() const
{
    return label;
}

MyAddrContT const & CAccountReceiver::generateMyUsedAddresses()
{
    usedAddresses.clear();
    for(CPaymentChannel & pchannel: pchannels) {
        MyAddrContT const & addrs = pchannel.generateMyUsedAddresses();
        usedAddresses.insert(usedAddresses.end(), addrs.begin(), addrs.end());
    }
    return usedAddresses;
}

MyAddrContT const & CAccountReceiver::generateMyNextAddresses()
{
    nextAddresses.clear();
    nextAddresses.emplace_back(getMyPcode().getNotificationAddress(), bip47::utils::derive(privkey, {0}).key);
    for(CPaymentChannel & pchannel: pchannels) {
        MyAddrContT const & addrs = pchannel.generateMyNextAddresses();
        nextAddresses.insert(nextAddresses.end(), addrs.begin(), addrs.end());
    }
    return nextAddresses;
}

bool CAccountReceiver::markAddressUsed(CBitcoinAddress const & address)
{
    for(PChannelContT::iterator iter = pchannels.begin(); iter != pchannels.end(); ++iter) {
        if(iter->markAddressUsed(address)) {
            generateMyNextAddresses();
            return true;
        }
    }
    return false;
}

bool CAccountReceiver::acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, COutPoint const & outpoint, CPubKey const & outpoinPubkey)
{
    CPaymentCode pcode;
    CExtKey pcodePrivkey = utils::derive(privkey, {uint32_t(pchannels.size())});
    try {
        if(!bip47::utils::pcodeFromMaskedPayload(maskedPayload, outpoint, pcodePrivkey.key, outpoinPubkey, pcode))
            return false;
    } catch (std::runtime_error const &) {
        return false;
    }
    if(findTheirPcode(pcode))
        return true;
    pchannels.emplace_back(pcode, privkey, CPaymentChannel::Side::receiver);
    return true;
}

/******************************************************************************/

CWallet::CWallet(std::vector<unsigned char> const & seedData)
{
    CExtKey seedKey;
    seedKey.SetMaster(seedData.data(), seedData.size());
    privkey = utils::derive(seedKey, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});
}

CWallet::CWallet(uint256 const & seedData)
:CWallet({seedData.begin(), seedData.end()})
{}

CAccountReceiver & CWallet::createReceivingAccount(std::string const & label)
{
    size_t const accNum = (accounts.empty() ? 0 : accounts.cend()->first + 1);
    CAccountPtr pacc = std::shared_ptr<CAccountBase>(new CAccountReceiver(privkey, accNum, label));
    accounts.emplace(accNum, pacc);
    LogBip47("Added pcode: %s, notification address: %s\n", pacc->getMyPcode().toString(), pacc->getMyPcode().getNotificationAddress().ToString());
    return static_cast<CAccountReceiver &>(*pacc);
}

CAccountSender & CWallet::provideSendingAccount(CPaymentCode const & theirPcode)
{
    for(std::pair<size_t, CAccountPtr const> const & acc : accounts) {
        CAccountSender * pacc = dynamic_cast<CAccountSender *>(acc.second.get());
        if(pacc && pacc->getTheirPcode() == theirPcode)
            return *pacc;
    }
    size_t const accNum = (accounts.empty() ? 0 : accounts.cend()->first + 1);
    CAccountPtr pacc = std::shared_ptr<CAccountBase>(new CAccountSender(privkey, accNum, theirPcode));
    accounts.emplace(accNum, pacc);
    return static_cast<CAccountSender &>(*pacc);
}

}
