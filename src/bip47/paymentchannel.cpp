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

std::vector<CBIP47Address>& CBIP47PaymentChannel::getIncomingAddresses() {
    return incomingAddresses;
}

int CBIP47PaymentChannel::getCurrentIncomingIndex() {
    return currentIncomingIndex;
}

void CBIP47PaymentChannel::generateKeys(CWallet *bip47Wallet) {
    for(int i = 0; i < LOOKAHEAD; i++)
    {
        CPaymentCode pcode(paymentCode);
        CBIP47Account acc = bip47Wallet->getBIP47Account(myPaymentCode);
        CPaymentAddress paddr = CBIP47Util::getReceiveAddress(&acc, bip47Wallet, pcode, i);
        CKey newgenKey = paddr.getReceiveECKey();
        bip47Wallet->importKey(newgenKey);
        CBitcoinAddress btcAddr = bip47Wallet->getAddressOfKey(newgenKey.GetPubKey());
        LogPrintf("New Address generated %s\n", btcAddr.ToString());
        incomingAddresses.push_back(CBIP47Address(btcAddr.ToString(), i));
    }
    
    currentIncomingIndex = LOOKAHEAD - 1;
}

CBIP47Address* CBIP47PaymentChannel::getIncomingAddress(string address) {
    for (CBIP47Address bip47Address: incomingAddresses) {
        if (bip47Address.getAddress().compare(address)==0) {
            return &bip47Address; // lgtm [cpp/return-stack-allocated-memory]
        }
    }
    return nullptr;
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

std::vector<string>& CBIP47PaymentChannel::getOutgoingAddresses() {
    return outgoingAddresses;
}

bool CBIP47PaymentChannel::isNotificationTransactionSent() {
    return status == STATUS_SENT_CFM;
}

void CBIP47PaymentChannel::setStatusSent() {
    status = STATUS_SENT_CFM;
}

int CBIP47PaymentChannel::getCurrentOutgoingIndex() {
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
}
