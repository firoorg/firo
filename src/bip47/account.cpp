
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

CAccountBase::AddrContT const & CAccountBase::getMyUsedAddresses()
{
    return generateMyUsedAddresses();
}

CAccountBase::AddrContT const & CAccountBase::getMyNextAddresses()
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
        pchannel.emplace(theirPcode, privkey);
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

CAccountBase::AddrContT const & CAccountSender::generateMyUsedAddresses()
{
    return getPaymentChannel().generateMyUsedAddresses();
}

CAccountBase::AddrContT const & CAccountSender::generateMyNextAddresses()
{
    return getPaymentChannel().generateMyNextAddresses();
}

bool CAccountSender::markAddressUsed(CBitcoinAddress const & address)
{
    return getPaymentChannel().markAddressUsed(address);
}

/******************************************************************************/

CAccountReceiver::CAccountReceiver(CExtKey const & walletKey, size_t accountNum)
: CAccountBase(walletKey, accountNum)
{

}

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

CAccountBase::AddrContT const & CAccountReceiver::generateMyUsedAddresses()
{
    usedAddresses.clear();
    for(CPaymentChannel & pchannel: pchannels) {
        CPaymentChannel::AddrContT const & addrs = pchannel.generateMyUsedAddresses();
        usedAddresses.insert(usedAddresses.end(), addrs.begin(), addrs.end());
    }
    return usedAddresses;
}

CAccountBase::AddrContT const & CAccountReceiver::generateMyNextAddresses()
{
    nextAddresses.clear();
    nextAddresses.push_back(getMyNotificationAddress());
    for(CPaymentChannel & pchannel: pchannels) {
        CPaymentChannel::AddrContT const & addrs = pchannel.generateMyNextAddresses();
        nextAddresses.insert(nextAddresses.end(), addrs.begin(), addrs.end());
    }
    return nextAddresses;
}

bool CAccountReceiver::markAddressUsed(CBitcoinAddress const & address)
{
    if(address == getMyNotificationAddress())
        return true;

}

bool CAccountReceiver::acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, COutPoint const & outpoint)
{
    CDataStream ds(SER_NETWORK, 0);
    ds << outpoint;


}

/******************************************************************************/

CWallet::CWallet(std::vector<unsigned char> const & seedData)
{
    CExtKey seedKey;
    seedKey.SetMaster(seedData.data(), seedData.size());
    privkey = utils::derive(seedKey, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});
}

CAccountPtr CWallet::createReceivingAccount()
{
    size_t const accNum = (accounts.empty() ? 0 : accounts.cend()->first + 1);
    CAccountPtr pacc = std::shared_ptr<CAccountBase>(new CAccountReceiver(privkey, accNum));
    accounts.emplace(accNum, pacc).first->second;
    return pacc;
}

CAccountPtr CWallet::provideSendingAccount(CPaymentCode const & theirPcode)
{
    for(std::pair<size_t, CAccountPtr const> const & acc : accounts) {
        CAccountSender const * pacc = dynamic_cast<CAccountSender const *>(acc.second.get());
        if(pacc && pacc->getTheirPcode() == theirPcode)
            return acc.second;
    }
    size_t const accNum = (accounts.empty() ? 0 : accounts.cend()->first + 1);
    CAccountPtr pacc = std::shared_ptr<CAccountBase>(new CAccountSender(privkey, accNum, theirPcode));
    accounts.emplace(accNum, pacc);
    return pacc;
}

}
