#ifndef ZCOIN_BIP47CHANNEL_H
#define ZCOIN_BIP47CHANNEL_H

#include <string>

#include "serialize.h"
#include "streams.h"
#include "uint256.h"

#include "bip47/address.h"
#include "bip47/paymentcode.h"

class CWallet;

namespace bip47 {

class CPaymentChannel
{
public:
    enum State {
        created = 0,
        settingUp,  //Payment codes are being exchanged
        allSet      //Both payment codes are received
    };
public:
    CPaymentChannel();
    CPaymentChannel(CPaymentCode const & theirPcode, CExtKey const & myChannelKey);

    std::vector<CBitcoinAddress> generateTheirAddresses(size_t number) const;

    CPaymentCode const & getTheirPcode() const;
    CPaymentCode const & getMyPcode() const;

    std::vector<unsigned char> getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret) const;

    int getIdxRecv() const;
    int getIdxSend() const;

    std::string const & getLabel() const;
    void setLabel(std::string const & l);

    std::vector<CAddress> getIncomingAddresses() const;
    std::vector<string> getOutgoingAddresses() const;

    void generateKeys(CWallet* bip47Wallet);
    void addNewIncomingAddress(string newAddress, int nextIndex);
    bool isNotificationTransactionSent() const;
    void incrementOutgoingIndex();
    void addAddressToOutgoingAddresses(string address);
    void addTransaction(uint256 hash);
    void getTransactions(std::vector<uint256>& hashes) const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(theirPcode);
        READWRITE(payeePcode);
        READWRITE(label);
        READWRITE(idxRecv);
        READWRITE(idxSend);
        READWRITE(incomingAddresses);
        READWRITE(outgoingAddresses);
        READWRITE(transactions);
        uint8_t tmpState = state;
        READWRITE(tmpState);
        state = State(tmpState);
    }

private:
    CPaymentCode theirPcode, payeePcode;
    std::string label;
    std::vector<CAddress> incomingAddresses;
    std::vector<std::string> outgoingAddresses;
    std::vector<uint256> transactions;
    size_t idxSend;
    size_t idxRecv;
    State state;

    CExtKey myChannelKey;
};

}

#endif // ZCOIN_BIP47CHANNEL_H
