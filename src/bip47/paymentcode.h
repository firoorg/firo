#ifndef ZCOIN_BIP47PAYMENTCODE_H
#define ZCOIN_BIP47PAYMENTCODE_H
#include "bip47/utils.h"
#include "base58.h"
#include "crypto/hmac_sha512.h"
#include "bip47/channeladdress.h"
#include "chainparamsbase.h"

class CPaymentCode {

    public:
        CPaymentCode();
        CPaymentCode(std::string payment_code);
        CPaymentCode(unsigned char* payload, int length);
        CPaymentCode(std::vector<unsigned char> &v_pubkey, std::vector<unsigned char> &v_chain);
        CPaymentCode(unsigned char* v_pubkey, unsigned char* v_chain);
        CPaymentCode(const unsigned char* v_pubkey,  const unsigned char *v_chain);
        
        CBIP47ChannelAddress notificationAddress();

        CBIP47ChannelAddress addressAt(int idx);
        std::vector<unsigned char> getPayload();

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

        static int PUBLIC_KEY_Y_OFFSET;
        static int PUBLIC_KEY_X_OFFSET;
        static int CHAIN_OFFSET;
        static int PUBLIC_KEY_X_LEN;
        static int PUBLIC_KEY_Y_LEN;
        static int PUBLIC_KEY_COMPRESSED_LEN;
        static int CHAIN_CODE_LEN;
        static int PAYLOAD_LEN;
        static int PAYMENT_CODE_LEN;
        std::string strPaymentCode;
        std::vector<unsigned char> pubkey;
        std::vector<unsigned char>  chaincode;
        bool valid;

};
#endif // ZCOIN_BIP47PAYMENTCODE_H
