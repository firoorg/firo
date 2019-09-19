#ifndef SECRET_H
#define SECRET_H
#include "bip47_common.h"
#include "key.h"
#include "pubkey.h"
class SecretPoint {
    private:
        CKey  privKey ;
        secp256k1_pubkey pubKey ;

    public:
    SecretPoint() {
    }

    SecretPoint(std::vector<unsigned char> dataPrv, std::vector<unsigned char> dataPub)
    {
        privKey = loadPrivateKey(dataPrv);
        loadPublicKey(dataPub);
    }

    CKey& getPrivKey() {
        return privKey;
    }

    void setPrivKey(CKey &v_privKey) {
        privKey = v_privKey;
    }

    secp256k1_pubkey& getPubKey() {
        return pubKey;
    }

    void setPubKey(secp256k1_pubkey &v_pubKey) {
        pubKey = v_pubKey;
    }

    std::vector<unsigned char> ECDHSecretAsBytes(){
        std::vector<unsigned char> ret;
        return ret;
        // return this.ECDHSecret().getEncoded();
    }

    boolean isShared(SecretPoint secret) {
        return equals(secret);
    }

    private:
    std::vector<unsigned char> ECDHSecret() {
        std::vector<unsigned char> pubkey_hash(32, 0);
        secp256k1_context *context = OpenSSLContext::get_context();
        // We use secp256k1_ecdh instead of secp256k1_serialize_pubkey to avoid a timing channel.
        if (1 != secp256k1_ecdh(context, pubkey_hash.data(), &pubKey,privKey.begin())) {
            throw std::runtime_error("Unable to compute public key hash with secp256k1_ecdh.");
        }
        std::vector<unsigned char> hash(CSHA256::OUTPUT_SIZE);
        CSHA256().Write(pubkey_hash.data(), pubkey_hash.size()).Finalize(hash.data());
        return hash;
    }

    boolean equals(SecretPoint &v_secret){
        String str1 = HexStr(ECDHSecretAsBytes());
        String str2 = HexStr(v_secret.ECDHSecretAsBytes());
        if(str1.compare(str2)==0)
            return true ;
        return false ;
    }

    void loadPublicKey(std::vector<unsigned char> data){
        // secp256k1_context *context = OpenSSLContext::get_context();
        // secp256k1_ec_pubkey_parse(context,&pubKey,data.data(),data.size());
    }

    CKey loadPrivateKey(std::vector<unsigned char> data) {
        // ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(1, data), params);
        // return this.kf.generatePrivate(prvkey);
    }
};



#endif