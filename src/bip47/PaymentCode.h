#ifndef PAYMENTCODE_H
#define PAYMENTCODE_H
#include "bip47_common.h"
#include "base58.h"
#include "crypto/hmac_sha512.h"
#include "Bip47ChannelAddress.h"
#include "chainparamsbase.h"

class PaymentCode {
    private:
    static  int PUBLIC_KEY_Y_OFFSET ;
    static int PUBLIC_KEY_X_OFFSET ;
    static int CHAIN_OFFSET ;
    static int PUBLIC_KEY_X_LEN ;
    static int PUBLIC_KEY_Y_LEN;
    static int CHAIN_LEN ;
    static int PAYLOAD_LEN ;
    String strPaymentCode;
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char>  chain;

    public:
    PaymentCode() ;
    PaymentCode(String payment_code) ;
    PaymentCode(unsigned char* payload, int length) ;
    PaymentCode(std::vector<unsigned char> &v_pubkey, std::vector<unsigned char> &v_chain) ;
    PaymentCode(unsigned char* v_pubkey, unsigned char* v_chain) ;
    PaymentCode(const unsigned char* v_pubkey,  const unsigned char *v_chain) ;
    
    Bip47ChannelAddress notificationAddress();

    Bip47ChannelAddress addressAt(int idx) ;
    std::vector<unsigned char> getPayload() ;

    int getType()  ;

    std::vector<unsigned char> decode() ;

    std::vector<unsigned char> decodeChecked() ;

    std::vector<unsigned char>& getPubKey() ;
    std::vector<unsigned char>& getChain() ;

    string toString() ;

    static std::vector<unsigned char> getMask(std::vector<unsigned char> sPoint, std::vector<unsigned char> oPoint) ;
    static std::vector<unsigned char> blind(std::vector<unsigned char> payload, std::vector<unsigned char> mask) ;

    private:
    bool parse() ;

    string makeV1() ;

    string makeV2() ;

    string make(int type) ;
    
    static std::vector<unsigned char> vector_xor(std::vector<unsigned char> a, std::vector<unsigned char> b) ;
    public:
    bool isValid() ;
    static bool createMasterPubKeyFromPaymentCode(string payment_code_str,CExtPubKey &masterPubKey) ;
    static bool createMasterPubKeyFromBytes(std::vector<unsigned char> &pub, std::vector<unsigned char> &chain,CExtPubKey &masterPubKey) ;

    
};
#endif
