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

        std::vector<unsigned char> getEcdhSecret() const;

        bool isShared(SecretPoint const & secret) const;

    private:
        bool equals(SecretPoint const & v_secret) const;

        void loadPublicKey(std::vector<unsigned char> data);
        void loadPrivateKey(std::vector<unsigned char> data);

        CKey privKey;
        secp256k1_pubkey pubKey;

};
#endif // ZCOIN_BIP47SECRETPOINT_H
