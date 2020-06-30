#ifndef ZCOIN_BIP47SECRETPOINT_H
#define ZCOIN_BIP47SECRETPOINT_H
#include "bip47/utils.h"
#include "key.h"
#include "pubkey.h"
#include "sigma/openssl_context.h"

class SecretPoint {

    public:
        SecretPoint();
        SecretPoint(std::vector<unsigned char> dataPrv, std::vector<unsigned char> dataPub);

        CKey& getPrivKey();
        void setPrivKey(CKey &v_privKey);

        secp256k1_pubkey& getPubKey();
        void setPubKey(secp256k1_pubkey &v_pubKey);

        std::vector<unsigned char> ECDHSecretAsBytes();

        bool isShared(SecretPoint secret);

    private:
        std::vector<unsigned char> ECDHSecret();

        bool equals(SecretPoint &v_secret);

        void loadPublicKey(std::vector<unsigned char> data);
        void loadPrivateKey(std::vector<unsigned char> data);

        CKey privKey;
        secp256k1_pubkey pubKey;

};
#endif // ZCOIN_BIP47SECRETPOINT_H
