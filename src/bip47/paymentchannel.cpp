#include "bip47/paymentchannel.h"
#include "bip47/utils.h"
#include "bip47/address.h"
#include "bip47/paymentaddress.h"
#include "bip47/utils.h"
#include "wallet/wallet.h"

namespace bip47 {

int CPaymentChannel::LOOKAHEAD = 10;
CPaymentChannel::CPaymentChannel()
: idxSend(0), idxRecv(0), state(State::created)
{}

CPaymentChannel::CPaymentChannel(CPaymentCode const & myPcode, CPaymentCode const & theirPcode)
: myPcode(myPcode), theirPcode(theirPcode), idxSend(0), idxRecv(0), state(State::created)
{}

CPaymentCode const & CPaymentChannel::getMyPCode() const
{
    return myPcode;
}

CPaymentCode const & CPaymentChannel::getTheirPCode() const
{
    return theirPcode;
}

std::vector<CAddress> CPaymentChannel::getIncomingAddresses() const
{
    return incomingAddresses;
}

int CPaymentChannel::getIdxRecv() const
{
    return idxRecv;
}

void CPaymentChannel::generateKeys(CWallet *bip47Wallet)
{
    for(int i = 0; i < LOOKAHEAD; i++)
    {
        CAccount acc = bip47Wallet->getBIP47Account(myPcode.toString());
        int nextIndex = idxRecv + 1 + i;
        CPaymentAddress paddr = utils::getReceiveAddress(&acc, bip47Wallet, myPcode, nextIndex);
        CKey newgenKey = paddr.getReceiveECKey();
        bip47Wallet->importKey(newgenKey);
        CBitcoinAddress btcAddr = bip47Wallet->getAddressOfKey(newgenKey.GetPubKey());
        bip47Wallet->SetAddressBook(btcAddr.Get(), "BIP47PAYMENT-" + myPcode.toString() + "-" + std::to_string(nextIndex), "receive");
        incomingAddresses.push_back(CAddress(btcAddr.ToString(), nextIndex));
    }
    
    idxRecv = idxRecv + LOOKAHEAD;
}

CAddress const * CPaymentChannel::getIncomingAddress(string address) const
{
    for (CAddress const & bip47Address: incomingAddresses) {
        if (bip47Address.getAddress().compare(address)==0) {
            return &bip47Address;
        }
    }
    return nullptr;
}

void CPaymentChannel::addTransaction(uint256 hash)
{   if (hash.IsNull()) return;
    if (std::find(transactions.begin(), transactions.end(), hash) != transactions.end()) return;
    transactions.push_back(hash);
}
void CPaymentChannel::getTransactions(std::vector<uint256>& hashes) const
{
    hashes.insert(hashes.end(), transactions.begin(), transactions.end());
}

void CPaymentChannel::addNewIncomingAddress(string newAddress, int nextIndex)
{
    incomingAddresses.push_back(CAddress(newAddress, nextIndex));      
    idxRecv = nextIndex;
}

std::string const & CPaymentChannel::getLabel() const
{
    return label;
}

void CPaymentChannel::setLabel(std::string const & l)
{
    label = l;
}

std::vector<string> CPaymentChannel::getOutgoingAddresses() const
{
    return outgoingAddresses;
}

int CPaymentChannel::getIdxSend() const
{
    return idxSend;
}

void CPaymentChannel::incrementOutgoingIndex()
{
    idxSend++;
}

void CPaymentChannel::addAddressToOutgoingAddresses(string address)
{
    outgoingAddresses.push_back(address);
}

bool CPaymentChannel::isNotificationTransactionSent() const
{
    return false;
}

}
