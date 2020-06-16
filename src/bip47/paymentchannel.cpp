#include "bip47/paymentchannel.h"
#include "bip47/utils.h"
#include "bip47/address.h"
#include "bip47/paymentaddress.h"
#include "wallet/wallet.h"



string Bip47PaymentChannel::TAG = "Bip47PaymentChannel";

int Bip47PaymentChannel::STATUS_NOT_SENT = -1;
int Bip47PaymentChannel::STATUS_SENT_CFM = 1;
int Bip47PaymentChannel::LOOKAHEAD = 10;
Bip47PaymentChannel::Bip47PaymentChannel()     
: status(STATUS_NOT_SENT),
currentOutgoingIndex(0),
currentIncomingIndex(-1)
{}

Bip47PaymentChannel::Bip47PaymentChannel(string v_paymentCode)
: status(STATUS_NOT_SENT),
currentOutgoingIndex(0),
currentIncomingIndex(-1)
{
    paymentCode = v_paymentCode;
}

Bip47PaymentChannel::Bip47PaymentChannel(string v_paymentCode, string v_label) {
    paymentCode = v_paymentCode;
    label = v_label;
}

string Bip47PaymentChannel::getPaymentCode() {
    return paymentCode;
}

void Bip47PaymentChannel::setPaymentCode(string pc) {
    paymentCode = pc;
}

std::vector<Bip47Address>& Bip47PaymentChannel::getIncomingAddresses() {
    return incomingAddresses;
}

int Bip47PaymentChannel::getCurrentIncomingIndex() {
    return currentIncomingIndex;
}

void Bip47PaymentChannel::generateKeys(CWallet *bip47Wallet) {
    for(int i = 0; i < LOOKAHEAD; i++)
    {
        PaymentCode pcode(paymentCode);
        PaymentAddress paddr = BIP47Util::getReceiveAddress(bip47Wallet, pcode, i);
        CKey newgenKey = paddr.getReceiveECKey();
        bip47Wallet->importKey(newgenKey);
        CBitcoinAddress btcAddr = bip47Wallet->getAddressOfKey(newgenKey.GetPubKey());
        LogPrintf("New Address generated %s\n", btcAddr.ToString());
        incomingAddresses.push_back(Bip47Address(btcAddr.ToString(), i));
    }
    
    currentIncomingIndex = LOOKAHEAD - 1;
}

Bip47Address* Bip47PaymentChannel::getIncomingAddress(string address) {
    for (Bip47Address bip47Address: incomingAddresses) {
        if (bip47Address.getAddress().compare(address)==0) {
            return &bip47Address; // lgtm [cpp/return-stack-allocated-memory]
        }
    }
    return nullptr;
}

void Bip47PaymentChannel::addNewIncomingAddress(string newAddress, int nextIndex) {
    incomingAddresses.push_back(Bip47Address(newAddress, nextIndex));      
    currentIncomingIndex = nextIndex;
}

string Bip47PaymentChannel::getLabel() const {
    return label;
}

void Bip47PaymentChannel::setLabel(string l) {
    label = l;
}

std::vector<string>& Bip47PaymentChannel::getOutgoingAddresses() {
    return outgoingAddresses;
}

bool Bip47PaymentChannel::isNotificationTransactionSent() {
    return status == STATUS_SENT_CFM;
}

void Bip47PaymentChannel::setStatusSent() {
    status = STATUS_SENT_CFM;
}

int Bip47PaymentChannel::getCurrentOutgoingIndex() {
    return currentOutgoingIndex;
}

void Bip47PaymentChannel::incrementOutgoingIndex() {
    currentOutgoingIndex++;
}

void Bip47PaymentChannel::addAddressToOutgoingAddresses(string address) {
    outgoingAddresses.push_back(address);
}

void Bip47PaymentChannel::setStatusNotSent() {
    status = STATUS_NOT_SENT;
}
