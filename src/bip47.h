//
// Created by Top1s on 8/22/2019.
//

#ifndef ZCOIN_BIP47_H
#define ZCOIN_BIP47_H

#include "pubkey.h"
#include "base58.h"
#include "wallet/wallet.h"
#include <vector>
#include <string>


namespace bip47 {

    using namespace std;
    using byte = unsigned char;

    inline byte* xor_array(byte* a1, byte* a2, byte* ret, int length) {
        for(int i = 0; i < length; i++) {
            ret[i] = a1[i] ^ a2[i];
        }
        return ret;
    }

    class SecretPoint {

    public:
        SecretPoint(CPrivKey cPrivKey, CPubKey cPubKey);
    };

    class PaymentCode {

    private:
        static const int PUBLIC_KEY_Y_OFFSET = 2;
        static const int PUBLIC_KEY_X_OFFSET = 3;
        static const int CHAIN_OFFSET = 35;
        static const int PUBLIC_KEY_X_LEN = 32;
        static const int PUBLIC_KEY_LEN = 33;
        static const int PUBLIC_KEY_Y_LEN = 1;
        static const int CHAIN_LEN = 32;
        static const int PAYLOAD_LEN = 80;

        std::string strPaymentCode;
        byte pubkey[PUBLIC_KEY_LEN];
        byte chain[CHAIN_LEN];

    public:
//        CKeyID masterKeyID;


        static const int VERSION_BASIC = 1;
        static const int VERSION_WITH_BIP47 = 1;
        static const int CURRENT_VERSION = VERSION_WITH_BIP47;

        bool valid();
        PaymentCode();
        PaymentCode(byte *pkey, byte *ch);
        PaymentCode(CPubKey cPubKey, ChainCode chainCode);
        PaymentCode(string payment_code);
        bool parse_payment_code();
        vector<byte> getPubkey();

        CPubKey getMasterPubkey();
        bool get_mask(byte* mask, CKey designated, CPubKey bobPubkey, byte* outpoint);
        bool get_payload(byte* payload);



        static const std::vector<unsigned char> blind(unsigned char* payload, unsigned char* mask) {
            byte ret[PAYLOAD_LEN] = {};
            byte pubkey[PUBLIC_KEY_X_LEN] = {};
            byte chain[CHAIN_LEN] = {};
            byte buf0[PUBLIC_KEY_X_LEN] = {};
            byte buf1[CHAIN_LEN] = {};

            memcpy(ret, payload, PAYLOAD_LEN);
            memcpy(pubkey, payload + PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN);
            memcpy(chain, payload + CHAIN_OFFSET, CHAIN_LEN);
            memcpy(buf0, mask, PUBLIC_KEY_X_LEN);
            memcpy(buf1, mask + PUBLIC_KEY_X_LEN, CHAIN_LEN);

            byte masked1[PUBLIC_KEY_X_LEN];
            byte masked2[CHAIN_LEN];
            xor_array(pubkey, buf0, masked1, PUBLIC_KEY_X_LEN);
            xor_array(chain, buf1, masked2, CHAIN_LEN);

            memcpy(ret + PUBLIC_KEY_X_OFFSET, masked1, PUBLIC_KEY_X_LEN);
            memcpy(ret + CHAIN_OFFSET, masked2, CHAIN_LEN);

            std::vector<unsigned char> blindpcode(ret, ret + PAYLOAD_LEN);
            return blindpcode;
        }

        std::string makeV1();
        std::string ToString();
    };

    class Bip47Account {
    private:
        int accountId;
        PaymentCode paymentCode;

    public:
        Bip47Account(CExtKey coinTypeKey, int identity);
        Bip47Account(string strPaymentCode);
        string getStringPaymentCode();
        CBitcoinAddress getNotificationAddress();
        CExtKey key;
    };


    void makeNotificationTransaction(std::string payment_code);
    void signTransaction();
    PaymentCode getPaymentCodeInNotificationTransaction();
}

#endif //ZCOIN_BIP47_H

