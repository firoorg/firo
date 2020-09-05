#include "bip47/paymentchannel.h"
#include "bip47/utils.h"
#include "bip47/address.h"
#include "bip47/paymentaddress.h"
#include "wallet/wallet.h"



string CBIP47PaymentChannel::TAG = "CBIP47PaymentChannel";

int CBIP47PaymentChannel::STATUS_NOT_SENT = -1;
int CBIP47PaymentChannel::STATUS_SENT_CFM = 1;
int CBIP47PaymentChannel::LOOKAHEAD = 10;
CBIP47PaymentChannel::CBIP47PaymentChannel()     
: status(STATUS_NOT_SENT),
currentOutgoingIndex(0),
currentIncomingIndex(-1)
{}

CBIP47PaymentChannel::CBIP47PaymentChannel(string v_myPaymentCode, string v_paymentCode)
: status(STATUS_NOT_SENT),
currentOutgoingIndex(0),
currentIncomingIndex(-1)
{
    paymentCode = v_paymentCode;
    myPaymentCode = v_myPaymentCode;
}

CBIP47PaymentChannel::CBIP47PaymentChannel(string v_myPaymentCode, string v_paymentCode, string v_label) {
    paymentCode = v_paymentCode;
    label = v_label;
    myPaymentCode = v_myPaymentCode;
}

string CBIP47PaymentChannel::getPaymentCode() const {
    return paymentCode;
}

string CBIP47PaymentChannel::getMyPaymentCode() const {
    return myPaymentCode;
}

void CBIP47PaymentChannel::setPaymentCode(string pc) {
    paymentCode = pc;
}

uint256 CBIP47PaymentChannel::getNotificationTxHash() const
{
    return notiTxHash;
}

std::vector<CBIP47Address> CBIP47PaymentChannel::getIncomingAddresses() const {
    return incomingAddresses;
}

int CBIP47PaymentChannel::getCurrentIncomingIndex() const {
    return currentIncomingIndex;
}

void CBIP47PaymentChannel::generateKeys(CWallet *bip47Wallet) {
    for(int i = 0; i < LOOKAHEAD; i++)
    {
        CPaymentCode pcode(paymentCode);
        CBIP47Account acc = bip47Wallet->getBIP47Account(myPaymentCode);
        int nextIndex = currentIncomingIndex + 1 + i;
        LogPrintf("getting received address \n");
        CPaymentAddress paddr = CBIP47Util::getReceiveAddress(&acc, bip47Wallet, pcode, nextIndex);
        LogPrintf("finish getting received address \n");
        CKey newgenKey = paddr.getReceiveECKey();
        LogPrintf("finish new key gen \n");
        bip47Wallet->importKey(newgenKey);
        LogPrintf("imported new key gen \n");
        CBitcoinAddress btcAddr = bip47Wallet->getAddressOfKey(newgenKey.GetPubKey());
        LogPrintf("New Address generated %s\n", btcAddr.ToString());
        bip47Wallet->SetAddressBook(btcAddr.Get(), "BIP47PAYMENT-" + paymentCode + "-" + std::to_string(nextIndex), "receive");
        incomingAddresses.push_back(CBIP47Address(btcAddr.ToString(), nextIndex));
    }
    
    currentIncomingIndex = currentIncomingIndex + LOOKAHEAD;
}

CBIP47Address* CBIP47PaymentChannel::getIncomingAddress(string address) {
    for (CBIP47Address bip47Address: incomingAddresses) {
        if (bip47Address.getAddress().compare(address)==0) {
            return &bip47Address; // lgtm [cpp/return-stack-allocated-memory]
        }
    }
    return nullptr;
}

void CBIP47PaymentChannel::addTransaction(uint256 hash)
{   if (hash.IsNull()) return;
    if (std::find(transactions.begin(), transactions.end(), hash) != transactions.end()) return;
    transactions.push_back(hash);
}
void CBIP47PaymentChannel::getTransactions(std::vector<uint256>& hashes) const
{
    hashes.insert(hashes.end(), transactions.begin(), transactions.end());
}

void CBIP47PaymentChannel::addNewIncomingAddress(string newAddress, int nextIndex) {
    incomingAddresses.push_back(CBIP47Address(newAddress, nextIndex));      
    currentIncomingIndex = nextIndex;
}

string CBIP47PaymentChannel::getLabel() const {
    return label;
}

void CBIP47PaymentChannel::setLabel(string l) {
    label = l;
}

std::vector<string> CBIP47PaymentChannel::getOutgoingAddresses() const {
    return outgoingAddresses;
}

bool CBIP47PaymentChannel::isNotificationTransactionSent() const {
    return status == STATUS_SENT_CFM;
}

void CBIP47PaymentChannel::setStatusSent(uint256 notiTxHash) {
    status = STATUS_SENT_CFM;
    this->notiTxHash = notiTxHash;
}

int CBIP47PaymentChannel::getCurrentOutgoingIndex() const {
    return currentOutgoingIndex;
}

void CBIP47PaymentChannel::incrementOutgoingIndex() {
    currentOutgoingIndex++;
}

void CBIP47PaymentChannel::addAddressToOutgoingAddresses(string address) {
    outgoingAddresses.push_back(address);
}

void CBIP47PaymentChannel::setStatusNotSent() {
    status = STATUS_NOT_SENT;
    this->notiTxHash.SetNull();
}
