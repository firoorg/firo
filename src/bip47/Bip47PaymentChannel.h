#ifndef BIP47CHANNEL_H
#define BIP47CHANNEL_H
#include "bip47_common.h"
#include "Bip47Address.h"
class Bip47Wallet;
class Bip47PaymentChannel {
    private:
     static String TAG ;

     static int STATUS_NOT_SENT ;
     static int STATUS_SENT_CFM ;
     static int LOOKAHEAD ;

     String paymentCode;
     String label;
     std::list<Bip47Address> incomingAddresses ;
     std::list<String> outgoingAddresses ;
     int status;
     int currentOutgoingIndex ;
     int currentIncomingIndex ;

    // private static final Logger log = LoggerFactory.getLogger(Bip47PaymentChannel.class);
    public:
        Bip47PaymentChannel() ;
        Bip47PaymentChannel(String v_paymentCode);
        Bip47PaymentChannel(String v_paymentCode, String v_label) ;
        String getPaymentCode() ;
        void setPaymentCode(String pc);
        std::list<Bip47Address>& getIncomingAddresses() ;
        int getCurrentIncomingIndex() ;
        void generateKeys(Bip47Wallet *bip47Wallet) ;
        Bip47Address* getIncomingAddress(String address) ;
        void addNewIncomingAddress(String newAddress, int nextIndex) ;
        String getLabel() ;
        void setLabel(String l) ;
        std::list<String>& getOutgoingAddresses() ;
        boolean isNotificationTransactionSent() ;
        void setStatusSent() ;
        int getCurrentOutgoingIndex() ;
        void incrementOutgoingIndex() ;
        void addAddressToOutgoingAddresses(String address) ;
        void setStatusNotSent() ;
};

#endif