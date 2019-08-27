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
    class payment_code {

    private:
        static int PUBLIC_KEY_Y_OFFSET;
        static int PUBLIC_KEY_X_OFFSET;
        static int CHAIN_OFFSET;
        static int PUBLIC_KEY_X_LEN;
        static int PUBLIC_KEY_Y_LEN;
        static int CHAIN_LEN;
        static int PAYLOAD_LEN;

    public:
        CKeyID masterKeyID;

        static const int VERSION_BASIC = 1;
        static const int VERSION_WITH_BIP47 = 1;
        static const int CURRENT_VERSION = VERSION_WITH_BIP47;

        bool valid() const;
        payment_code();

        static const std::vector<unsigned char> blind(unsigned char* payload, unsigned char* mask);

        std::string makeV1();
    };
}