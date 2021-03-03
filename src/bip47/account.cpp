
#include <thread>

#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "util.h"
#include "bip47/utils.h"
#include "wallet/wallet.h"
#include "lelantus.h"


namespace bip47 {

CAccountBase::CAccountBase()
:accountNum(0)
{
}

CAccountBase::CAccountBase(CExtKey const & walletKey, size_t accountNum)
:accountNum(accountNum)
{
    walletKey.Derive(privkey, (unsigned int)(accountNum) | BIP32_HARDENED_KEY_LIMIT);
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

size_t CAccountBase::getAccountNum() const
{
    return accountNum;
}

CKey const & CAccountBase::getMyNotificationKey() const
{
    if(!myNotificationKey) {
        myNotificationKey.emplace(utils::Derive(privkey, {0}).key);
    }
    return *myNotificationKey;
}


/******************************************************************************/

CAccountSender::CAccountSender(CExtKey const & walletKey, size_t accountNum, CPaymentCode const & theirPcode)
: CAccountBase(walletKey, accountNum), theirPcode(theirPcode)
{
    updateMyNextAddresses();
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

CBitcoinAddress CAccountSender::generateTheirNextSecretAddress()
{
    return getPaymentChannel().generateTheirNextSecretAddress();
}

void CAccountSender::updateMyNextAddresses()
{
    nextAddresses.clear();
    nextAddresses.push_back({getPaymentChannel().getMyPcode().getNotificationAddress(), getMyNotificationKey()});
}

MyAddrContT const & CAccountSender::generateMyUsedAddresses()
{
    return getPaymentChannel().generateMyUsedAddresses();
}

MyAddrContT const & CAccountSender::generateMyNextAddresses()
{
    return nextAddresses;
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

CAccountReceiver::PChannelContT const & CAccountReceiver::getPchannels() const
{
    return pchannels;
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
    nextAddresses.emplace_back(getMyNotificationAddress(), getMyNotificationKey());
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

void CAccountReceiver::acceptPcode(CPaymentCode const & theirPcode)
{
    if(findTheirPcode(theirPcode))
        return;
    pchannels.emplace_back(theirPcode, privkey, CPaymentChannel::Side::receiver);
}

bool CAccountReceiver::acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, COutPoint const & outpoint, CPubKey const & outpoinPubkey)
{
    std::unique_ptr<CPaymentCode> pcode;
    CExtKey pcodePrivkey = utils::Derive(privkey, {0});
    try {
        pcode = bip47::utils::PcodeFromMaskedPayload(maskedPayload, outpoint, pcodePrivkey.key, outpoinPubkey);
        if(!pcode)
            return false;
    } catch (std::runtime_error const &) {
        return false;
    }
    acceptPcode(*pcode);
    return true;
}

bool CAccountReceiver::acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, CTxIn const & in)
{
    std::unique_ptr<lelantus::JoinSplit> jsplit = lelantus::ParseLelantusJoinSplit(in);
    if(!jsplit)
        return false;
    std::unique_ptr<CPaymentCode> pcode;
    CExtKey pcodePrivkey = utils::Derive(privkey, {0});
    try {
        CDataStream ds(SER_NETWORK, 0);
        ds << jsplit->getCoinSerialNumbers()[0];
        pcode = bip47::utils::PcodeFromMaskedPayload(maskedPayload, (unsigned char const *)ds.vch.data(), ds.vch.size(), pcodePrivkey.key, jsplit->GetEcdsaPubkeys()[0]);
        if(!pcode)
            return false;
    } catch (std::runtime_error const &) {
        return false;
    }
    acceptPcode(*pcode);
    return true;
}

CPaymentCode const & CAccountReceiver::lastPcode() const
{
    return pchannels.back().getTheirPcode();
}

/******************************************************************************/

CWallet::CWallet(std::vector<unsigned char> const & seedData)
{
    CExtKey seedKey;
    seedKey.SetMaster(seedData.data(), seedData.size());
    privkeySend = utils::Derive(seedKey, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0});
    privkeyReceive = utils::Derive(seedKey, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 1});
}

CWallet::CWallet(uint256 const & seedData)
:CWallet({seedData.begin(), seedData.end()})
{}

CAccountReceiver & CWallet::createReceivingAccount(std::string const & label)
{
    size_t const accNum = (accReceivers.empty() ? 0 : accReceivers.rbegin()->first + 1);
    accReceivers.emplace(accNum, CAccountReceiver(privkeyReceive, accNum, label));
    CAccountReceiver & acc = accReceivers.rbegin()->second;
    LogBip47("Created for receiving: pcode: %s, naddr: %s, accNum: %d\n", acc.getMyPcode().toString(), acc.getMyPcode().getNotificationAddress().ToString(), accNum);
    return acc;
}

CAccountSender & CWallet::provideSendingAccount(CPaymentCode const & theirPcode)
{
    for(std::pair<size_t const, CAccountSender> & acc : accSenders) {
        if(acc.second.getTheirPcode() == theirPcode)
            return acc.second;
    }
    size_t const accNum = (accSenders.empty() ? 0 : accSenders.rbegin()->first + 1);
    accSenders.emplace(accNum, CAccountSender(privkeySend, accNum, theirPcode));
    CAccountSender & acc = accSenders.rbegin()->second;
    LogBip47("Created for sending to pcode: %s, accNum: %s, myPcode: %s\n", theirPcode.toString().c_str(), accNum, acc.getMyPcode().toString().c_str());
    return acc;
}

void CWallet::readReceiver(CAccountReceiver && receiver)
{
    if(accReceivers.find(receiver.getAccountNum()) != accReceivers.end())
        throw std::runtime_error("There is already an account with number " + std::to_string(receiver.getAccountNum()));
    accReceivers.insert(std::pair<size_t, CAccountReceiver>(receiver.getAccountNum(), std::move(receiver)));
}

void CWallet::readSender(CAccountSender && sender)
{
    if(accSenders.find(sender.getAccountNum()) != accSenders.end())
        throw std::runtime_error("There is already an account with number " + std::to_string(sender.getAccountNum()));
    accSenders.insert(std::pair<size_t, CAccountSender>(sender.getAccountNum(), std::move(sender)));
}

}
