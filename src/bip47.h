//
// Created by Top1s on 8/22/2019.
//

#ifndef ZCOIN_BIP47_H
#define ZCOIN_BIP47_H

#endif //ZCOIN_BIP47_H

#include "pubkey.h"
#include <vector>
#include <string>

const uint32_t BIP47_INDEX = 0x2F;

namespace bip47 {

    using byte = unsigned char;

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
        PaymentCode(byte pkey[PUBLIC_KEY_LEN], byte ch[CHAIN_LEN]);
        PaymentCode(string payment_code);
        bool parse_payment_code();
        vector<byte> getPubkey();

        CPubKey getMasterPubkey();


        static const std::vector<unsigned char> blind(unsigned char* payload, unsigned char* mask);

        std::string makeV1();
    };
}