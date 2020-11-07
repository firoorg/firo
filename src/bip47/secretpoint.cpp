#include "sigma/coin.h"
#include "bip47/secretpoint.h"
#include "sigma/openssl_context.h"
#include "bip47/utils.h"


namespace bip47 {

SecretPoint::SecretPoint() {
}

SecretPoint::SecretPoint(std::vector<unsigned char> const & dataPrv, std::vector<unsigned char> const & dataPub)
{
    loadPrivateKey(dataPrv);
    loadPublicKey(dataPub);
}

CKey const & SecretPoint::getPrivKey() const {
    return privKey;
}

void SecretPoint::setPrivKey(CKey const & v_privKey) {
    privKey = v_privKey;
}

secp256k1_pubkey const & SecretPoint::getPubKey() const {
    return pubKey;
}

void SecretPoint::setPubKey(secp256k1_pubkey const & v_pubKey) {
    pubKey = v_pubKey;
}

bool SecretPoint::isShared(SecretPoint const & secret) const {
    return equals(secret);
}

std::vector<unsigned char> SecretPoint::getEcdhSecret() const {
    std::vector<unsigned char> pubkey_hash(32, 0);
    secp256k1_context *context = OpenSSLContext::get_context();
    // We use secp256k1_ecdh instead of secp256k1_serialize_pubkey to avoid a timing channel.
    if (1 != secp256k1_ecdh(context, pubkey_hash.data(), &pubKey, privKey.begin())) {
        throw std::runtime_error("Unable to compute public key hash with secp256k1_ecdh.");
    }
    std::vector<unsigned char> hash(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(pubkey_hash.data(), pubkey_hash.size()).Finalize(hash.data());
    return hash;
}

bool SecretPoint::equals(SecretPoint const & v_secret) const {
    std::vector<unsigned char> const v1 = getEcdhSecret()
        , v2 = v_secret.getEcdhSecret();
    return v1 == v2;
}

void SecretPoint::loadPublicKey(std::vector<unsigned char> const & data) {
    secp256k1_context *context = OpenSSLContext::get_context();
    secp256k1_ec_pubkey_parse(context,&pubKey,data.data(),data.size());
}

void SecretPoint::loadPrivateKey(std::vector<unsigned char> const & data) {
    privKey.Set(data.begin(),data.end(),false);
}

}
