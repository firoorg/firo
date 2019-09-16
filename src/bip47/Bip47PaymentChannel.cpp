#include "Bip47PaymentChannel.h"
#include "Bip47Wallet.h"

String Bip47PaymentChannel::TAG = "Bip47PaymentChannel";

int Bip47PaymentChannel::STATUS_NOT_SENT = -1;
int Bip47PaymentChannel::STATUS_SENT_CFM = 1;
int Bip47PaymentChannel::LOOKAHEAD = 10;
Bip47PaymentChannel::Bip47PaymentChannel()     
: status(STATUS_NOT_SENT),
currentOutgoingIndex(0),
currentIncomingIndex(-1)
{}

Bip47PaymentChannel::Bip47PaymentChannel(String v_paymentCode)
: status(STATUS_NOT_SENT),
currentOutgoingIndex(0),
currentIncomingIndex(-1)
{
    paymentCode = v_paymentCode;
}

Bip47PaymentChannel::Bip47PaymentChannel(String v_paymentCode, String v_label) {
    paymentCode = v_paymentCode ;
    label = v_label;
}

String Bip47PaymentChannel::getPaymentCode() {
    return paymentCode;
}

void Bip47PaymentChannel::setPaymentCode(String pc) {
    paymentCode = pc;
}

std::list<Bip47Address>& Bip47PaymentChannel::getIncomingAddresses() {
    return incomingAddresses;
}

int Bip47PaymentChannel::getCurrentIncomingIndex() {
    return currentIncomingIndex;
}

void Bip47PaymentChannel::generateKeys(Bip47Wallet *bip47Wallet) {
//     for (int i = 0; i < LOOKAHEAD; i++) {
//         ECKey key = BIP47Util.getReceiveAddress(bip47Wallet, paymentCode, i).getReceiveECKey();
//         Address address = bip47Wallet->getAddressOfKey(key);

//         log.debug("New address generated");
//         log.debug(address.toString());
//         bip47Wallet->importKey(key);
// //            incomingAddresses.add(i, new Bip47Address(address.toString(), i));
//         incomingAddresses.push_back(Bip47Address(address.toString(), i));

//     }

//     currentIncomingIndex = LOOKAHEAD - 1;
}

Bip47Address* Bip47PaymentChannel::getIncomingAddress(String address) {
    for (Bip47Address bip47Address: incomingAddresses) {
        if (bip47Address.getAddress().compare(address)==0) {
            return &bip47Address;
        }
    }
    return null;
}

void Bip47PaymentChannel::addNewIncomingAddress(String newAddress, int nextIndex) {
    //incomingAddresses.add(nextIndex, new Bip47Address(newAddress, nextIndex));
    incomingAddresses.push_back(Bip47Address(newAddress, nextIndex));      
    currentIncomingIndex = nextIndex;
}

String Bip47PaymentChannel::getLabel() {
    return label;
}

void Bip47PaymentChannel::setLabel(String l) {
    label = l;
}

std::list<String>& Bip47PaymentChannel::getOutgoingAddresses() {
    return outgoingAddresses;
}

boolean Bip47PaymentChannel::isNotificationTransactionSent() {
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

void Bip47PaymentChannel::addAddressToOutgoingAddresses(String address) {
    outgoingAddresses.push_back(address);
}

void Bip47PaymentChannel::setStatusNotSent() {
    status = STATUS_NOT_SENT;
}