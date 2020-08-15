#ifndef ZCOIN_BIP47CHANNEL_H
#define ZCOIN_BIP47CHANNEL_H
#include "bip47/utils.h"
#include "bip47/address.h"
#include <string>
#include "serialize.h"
#include "streams.h"


class CWallet;

class CBIP47PaymentChannel {

    public:
        CBIP47PaymentChannel();
        CBIP47PaymentChannel(string v_myPaymentCode, string v_paymentCode);
        CBIP47PaymentChannel(string v_myPaymentCode, string v_paymentCode, string v_label);
        
        string getPaymentCode() const;
        string getMyPaymentCode() const;
        void setPaymentCode(string pc);
        std::vector<CBIP47Address>& getIncomingAddresses();
        int getCurrentIncomingIndex();
        void generateKeys(CWallet *bip47Wallet);
        CBIP47Address* getIncomingAddress(string address);
        void addNewIncomingAddress(string newAddress, int nextIndex);
        string getLabel() const;
        void setLabel(string l);
        std::vector<string>& getOutgoingAddresses();

        bool isNotificationTransactionSent();
        void setStatusSent();
        int getCurrentOutgoingIndex();
        void incrementOutgoingIndex();
        void addAddressToOutgoingAddresses(string address);
        void setStatusNotSent();
        
        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(paymentCode);
            READWRITE(label);
            READWRITE(status);
            READWRITE(currentIncomingIndex);
            READWRITE(currentOutgoingIndex);
            READWRITE(incomingAddresses);
            READWRITE(outgoingAddresses);
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
        
};
#endif // ZCOIN_BIP47CHANNEL_H
