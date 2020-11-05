#ifndef ZCOIN_BIP47SECRETPOINT_H
#define ZCOIN_BIP47SECRETPOINT_H
#include "key.h"
#include "pubkey.h"
#include "sigma/openssl_context.h"

namespace bip47 {

class SecretPoint {

    public:
        SecretPoint();
        SecretPoint(std::vector<unsigned char> const & dataPrv, std::vector<unsigned char> const & dataPub);

        CKey const & getPrivKey() const;
        void setPrivKey(CKey const & v_privKey);

        secp256k1_pubkey const & getPubKey() const;
        void setPubKey(secp256k1_pubkey const & v_pubKey);

        std::vector<unsigned char> getEcdhSecret() const;

        bool isShared(SecretPoint const & secret) const;

    private:
        bool equals(SecretPoint const & v_secret) const;

        void loadPublicKey(std::vector<unsigned char> const & data);
        void loadPrivateKey(std::vector<unsigned char> const & data);

        CKey privKey;
        secp256k1_pubkey pubKey;

};

}

#endif // ZCOIN_BIP47SECRETPOINT_H
