#ifndef ZCOIN_BIP47PAYMENTCODE_H
#define ZCOIN_BIP47PAYMENTCODE_H
#include "bip47/utils.h"
#include "base58.h"
#include "crypto/hmac_sha512.h"
#include "bip47/channeladdress.h"
#include "chainparamsbase.h"

namespace bip47 {

static const unsigned int BIP47_INDEX = 47;

class CPaymentCode {
public:
    CPaymentCode();
    CPaymentCode(std::string payment_code);
    CPaymentCode(unsigned char* payload, int length);
    CPaymentCode(std::vector<unsigned char> const & v_pubkey, std::vector<unsigned char> const & v_chain);

    CChannelAddress notificationAddress();

    CChannelAddress addressAt(int idx) const;
    std::vector<unsigned char> getPayload() const;

    int getVersion();

    std::vector<unsigned char> decode();
    std::vector<unsigned char> decodeChecked();
    std::vector<unsigned char>& getPubKey();
    std::vector<unsigned char>& getChainCode();

    string toString() const;

    static std::vector<unsigned char> getMask(std::vector<unsigned char> sPoint, std::vector<unsigned char> oPoint);
    static std::vector<unsigned char> blind(std::vector<unsigned char> payload, std::vector<unsigned char> mask);

    bool isValid();
    static bool createMasterPubKeyFromPaymentCode(string payment_code_str,CExtPubKey &masterPubKey);
    static bool createMasterPubKeyFromBytes(std::vector<unsigned char> &pub, std::vector<unsigned char> &chain,CExtPubKey &masterPubKey);
private:
    bool parse();
    string makeV1();
    string makeV2();
    string make(int version);

    static std::vector<unsigned char> vector_xor(std::vector<unsigned char> a, std::vector<unsigned char> b);

    static const int PUBLIC_KEY_Y_OFFSET = 2;
    static const int PUBLIC_KEY_X_OFFSET = 3;
    static const int CHAIN_OFFSET = 35;
    static const int PUBLIC_KEY_X_LEN = 32;
    static const int PUBLIC_KEY_Y_LEN = 1;
    static const int PUBLIC_KEY_COMPRESSED_LEN = PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN;
    static const int CHAIN_CODE_LEN = 32;
    static const int PAYLOAD_LEN = 80;
    static const int PAYMENT_CODE_LEN = PAYLOAD_LEN + 1; // (0x47("P") | payload)

    std::string strPaymentCode;
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char>  chaincode;
    bool valid;
};

}

#endif // ZCOIN_BIP47PAYMENTCODE_H
