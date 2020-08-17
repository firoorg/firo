#ifndef ZCOIN_BIP47CHANNEL_H
#define ZCOIN_BIP47CHANNEL_H
#include "bip47/address.h"
#include "bip47/utils.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include <string>


class CWallet;

class CBIP47PaymentChannel
{
public:
    CBIP47PaymentChannel();
    CBIP47PaymentChannel(string v_myPaymentCode, string v_paymentCode);
    CBIP47PaymentChannel(string v_myPaymentCode, string v_paymentCode, string v_label);

    string getPaymentCode() const;
    string getMyPaymentCode() const;
    void setPaymentCode(string pc);
    std::vector<CBIP47Address> getIncomingAddresses() const;
    int getCurrentIncomingIndex() const;
    void generateKeys(CWallet* bip47Wallet);
    CBIP47Address* getIncomingAddress(string address);
    void addNewIncomingAddress(string newAddress, int nextIndex);
    string getLabel() const;
    void setLabel(string l);
    std::vector<string> getOutgoingAddresses() const;
    uint256 getNotificationTxHash() const;
    bool isNotificationTransactionSent() const;
    void setStatusSent(uint256 notiTxHash);
    int getCurrentOutgoingIndex() const;
    void incrementOutgoingIndex();
    void addAddressToOutgoingAddresses(string address);
    void setStatusNotSent();

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(paymentCode);
        READWRITE(myPaymentCode);
        READWRITE(label);
        READWRITE(status);
        READWRITE(currentIncomingIndex);
        READWRITE(currentOutgoingIndex);
        READWRITE(incomingAddresses);
        READWRITE(outgoingAddresses);
        READWRITE(notiTxHash);
    }

private:
    static string TAG;

    static int STATUS_NOT_SENT;
    static int STATUS_SENT_CFM;
    static int LOOKAHEAD;
    string myPaymentCode;
    string paymentCode;
    string label;
    std::vector<CBIP47Address> incomingAddresses;
    std::vector<string> outgoingAddresses;
    int status;
    int currentOutgoingIndex;
    int currentIncomingIndex;
    uint256 notiTxHash;
};
#endif // ZCOIN_BIP47CHANNEL_H
