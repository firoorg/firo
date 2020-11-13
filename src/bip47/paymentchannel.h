#ifndef ZCOIN_BIP47CHANNEL_H
#define ZCOIN_BIP47CHANNEL_H
#include "bip47/address.h"
#include "bip47/paymentcode.h"
#include <string>
#include "serialize.h"
#include "streams.h"
#include "uint256.h"

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
    CPaymentChannel(CPaymentCode const & myPcode, CPaymentCode const & theirPcode);

    CPaymentCode const & getMyPCode() const;
    CPaymentCode const & getTheirPCode() const;

    int getIdxRecv() const;
    int getIdxSend() const;

    std::string const & getLabel() const;
    void setLabel(std::string const & l);
    
    std::vector<CAddress> getIncomingAddresses() const;
    std::vector<string> getOutgoingAddresses() const;
    
    
    void generateKeys(CWallet* bip47Wallet);
    CAddress const * getIncomingAddress(string address) const;
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
        READWRITE(myPcode);
        READWRITE(theirPcode);
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
    static int LOOKAHEAD;
    CPaymentCode myPcode;
    CPaymentCode theirPcode;
    std::string label;
    std::vector<CAddress> incomingAddresses;
    std::vector<std::string> outgoingAddresses;
    std::vector<uint256> transactions;
    size_t idxSend;
    size_t idxRecv;
    State state;
};

}

#endif // ZCOIN_BIP47CHANNEL_H
