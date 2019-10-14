#ifndef SECRET_H
#define SECRET_H
#include "bip47_common.h"
#include "key.h"
#include "pubkey.h"
#include "sigma/openssl_context.h"
class SecretPoint {
    private:
        CKey  privKey ;
        secp256k1_pubkey pubKey ;

    public:
    SecretPoint() ;

    SecretPoint(std::vector<unsigned char> dataPrv, std::vector<unsigned char> dataPub) ;

    CKey& getPrivKey() ;

    void setPrivKey(CKey &v_privKey) ;

    secp256k1_pubkey& getPubKey() ;

    void setPubKey(secp256k1_pubkey &v_pubKey) ;

    std::vector<unsigned char> ECDHSecretAsBytes() ;

    boolean isShared(SecretPoint secret) ;

    private:
    std::vector<unsigned char> ECDHSecret() ;

    boolean equals(SecretPoint &v_secret);

    void loadPublicKey(std::vector<unsigned char> data) ;
    void loadPrivateKey(std::vector<unsigned char> data) ;
};



#endif