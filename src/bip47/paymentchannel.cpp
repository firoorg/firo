#include "bip47/paymentchannel.h"
#include "bip47/utils.h"
#include "bip47/address.h"
#include "bip47/paymentaddress.h"
#include "bip47/utils.h"
#include "wallet/wallet.h"

namespace bip47 {

string CPaymentChannel::TAG = "CPaymentChannel";

int CPaymentChannel::STATUS_NOT_SENT = -1;
int CPaymentChannel::STATUS_SENT_CFM = 1;
int CPaymentChannel::LOOKAHEAD = 10;
CPaymentChannel::CPaymentChannel()     
: status(STATUS_NOT_SENT),
currentOutgoingIndex(0),
currentIncomingIndex(-1)
{}

CPaymentChannel::CPaymentChannel(string v_myPaymentCode, string v_paymentCode)
: status(STATUS_NOT_SENT),
currentOutgoingIndex(0),
currentIncomingIndex(-1)
{
    paymentCode = v_paymentCode;
    myPaymentCode = v_myPaymentCode;
}

CPaymentChannel::CPaymentChannel(string v_myPaymentCode, string v_paymentCode, string v_label) {
    paymentCode = v_paymentCode;
    label = v_label;
    myPaymentCode = v_myPaymentCode;
}

string CPaymentChannel::getPaymentCode() const {
    return paymentCode;
}

string CPaymentChannel::getMyPaymentCode() const {
    return myPaymentCode;
}

void CPaymentChannel::setPaymentCode(string pc) {
    paymentCode = pc;
}

uint256 CPaymentChannel::getNotificationTxHash() const
{
    return notiTxHash;
}

std::vector<CAddress> CPaymentChannel::getIncomingAddresses() const {
    return incomingAddresses;
}

int CPaymentChannel::getCurrentIncomingIndex() const {
    return currentIncomingIndex;
}

void CPaymentChannel::generateKeys(CWallet *bip47Wallet) {
    for(int i = 0; i < LOOKAHEAD; i++)
    {
        CPaymentCode pcode(paymentCode);
        CAccount acc = bip47Wallet->getBIP47Account(myPaymentCode);
        int nextIndex = currentIncomingIndex + 1 + i;
        CPaymentAddress paddr = utils::getReceiveAddress(&acc, bip47Wallet, pcode, nextIndex);
        CKey newgenKey = paddr.getReceiveECKey();
        bip47Wallet->importKey(newgenKey);
        CBitcoinAddress btcAddr = bip47Wallet->getAddressOfKey(newgenKey.GetPubKey());
        bip47Wallet->SetAddressBook(btcAddr.Get(), "BIP47PAYMENT-" + paymentCode + "-" + std::to_string(nextIndex), "receive");
        incomingAddresses.push_back(CAddress(btcAddr.ToString(), nextIndex));
    }
    
    currentIncomingIndex = currentIncomingIndex + LOOKAHEAD;
}

CAddress const * CPaymentChannel::getIncomingAddress(string address) const {
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

void CPaymentChannel::addNewIncomingAddress(string newAddress, int nextIndex) {
    incomingAddresses.push_back(CAddress(newAddress, nextIndex));      
    currentIncomingIndex = nextIndex;
}

string CPaymentChannel::getLabel() const {
    return label;
}

void CPaymentChannel::setLabel(string l) {
    label = l;
}

std::vector<string> CPaymentChannel::getOutgoingAddresses() const {
    return outgoingAddresses;
}

bool CPaymentChannel::isNotificationTransactionSent() const {
    return status == STATUS_SENT_CFM;
}

void CPaymentChannel::setStatusSent(uint256 notiTxHash) {
    status = STATUS_SENT_CFM;
    this->notiTxHash = notiTxHash;
}

int CPaymentChannel::getCurrentOutgoingIndex() const {
    return currentOutgoingIndex;
}

void CPaymentChannel::incrementOutgoingIndex() {
    currentOutgoingIndex++;
}

void CPaymentChannel::addAddressToOutgoingAddresses(string address) {
    outgoingAddresses.push_back(address);
}

void CPaymentChannel::setStatusNotSent() {
    status = STATUS_NOT_SENT;
    this->notiTxHash.SetNull();
}

}
