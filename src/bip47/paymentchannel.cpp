#include "bip47/paymentchannel.h"
#include "bip47/utils.h"
#include "bip47/address.h"
#include "bip47/paymentaddress.h"
#include "bip47/utils.h"
#include "wallet/wallet.h"

namespace bip47 {

namespace{
int LOOKAHEAD = 10;
}

CPaymentChannel::CPaymentChannel()
: idxSend(0), idxRecv(0), state(State::created), iamPayer(false)
{}

CPaymentChannel::CPaymentChannel(CPaymentCode const & payerPcode, CPaymentCode const & payeePcode)
: theirPcode(theirPcode), payeePcode(payeePcode), idxSend(0), idxRecv(0), state(State::created), iamPayer(false)
{}


CPaymentChannel::CPaymentChannel(CPaymentCode const & theirPcode, CPaymentCode const & payeePcode, CKey const & myMasterKey, bool iamPayer)
: theirPcode(theirPcode), payeePcode(payeePcode), idxSend(0), idxRecv(0), state(State::created), iamPayer(false), myMasterKey(myMasterKey)
{}

std::vector<CBitcoinAddress> CPaymentChannel::generateTheirAddresses(size_t number) const
{
    static GroupElement const G(GroupElement().set_base_g());
    std::vector<CBitcoinAddress> result;
    for(size_t i = 0; i < number; ++i) {
        CPubKey const theirPubkey = theirPcode.getNthPubkey(i).pubkey;
        CSecretPoint sp(myMasterKey, theirPubkey);
        std::vector<unsigned char> spBytes = sp.getEcdhSecret();

        std::vector<unsigned char> spHash(32);
        CSHA256().Write(spBytes.data(), spBytes.size()).Finalize(spHash.data());

        secp_primitives::GroupElement B = utils::GeFromPubkey(theirPubkey);
        secp_primitives::GroupElement Bprime = B + G *  secp_primitives::Scalar(spHash.data());
        CPubKey pubKeyN = utils::PubkeyFromGe(Bprime);

        result.emplace_back(pubKeyN.GetID());
    }

    return result;
}

CPaymentCode const & CPaymentChannel::getTheirPcode() const
{
    return theirPcode;
}

CPaymentCode const & CPaymentChannel::getMyPcode() const
{
    return payeePcode;
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
        CAccount acc = bip47Wallet->getBIP47Account(theirPcode.toString());
        int nextIndex = idxRecv + 1 + i;
        CPaymentAddress paddr = utils::getReceiveAddress(&acc, bip47Wallet, theirPcode, nextIndex);
        CKey newgenKey = paddr.getReceiveECKey();
        bip47Wallet->importKey(newgenKey);
        CBitcoinAddress btcAddr = bip47Wallet->getAddressOfKey(newgenKey.GetPubKey());
        bip47Wallet->SetAddressBook(btcAddr.Get(), "BIP47PAYMENT-" + theirPcode.toString() + "-" + std::to_string(nextIndex), "receive");
        incomingAddresses.push_back(CAddress(btcAddr.ToString(), nextIndex));
    }
    
    idxRecv = idxRecv + LOOKAHEAD;
}

void CPaymentChannel::addTransaction(uint256 hash)
{
    if (hash.IsNull()) return;
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
