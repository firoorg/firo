#include "sigma/coin.h"
#include "SecretPoint.h"

SecretPoint::SecretPoint() {
}

SecretPoint::SecretPoint(std::vector<unsigned char> dataPrv, std::vector<unsigned char> dataPub)
{
    privKey = loadPrivateKey(dataPrv);
    loadPublicKey(dataPub);
}

CKey& SecretPoint::getPrivKey() {
    return privKey;
}

void SecretPoint::setPrivKey(CKey &v_privKey) {
    privKey = v_privKey;
}

secp256k1_pubkey& SecretPoint::getPubKey() {
    return pubKey;
}

void SecretPoint::setPubKey(secp256k1_pubkey &v_pubKey) {
    pubKey = v_pubKey;
}

std::vector<unsigned char> SecretPoint::ECDHSecretAsBytes(){
    return ECDHSecret();
}

boolean SecretPoint::isShared(SecretPoint secret) {
    return equals(secret);
}

std::vector<unsigned char> SecretPoint::ECDHSecret() {
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

boolean SecretPoint::equals(SecretPoint &v_secret){
    String str1 = HexStr(ECDHSecretAsBytes());
    String str2 = HexStr(v_secret.ECDHSecretAsBytes());
    if(str1.compare(str2)==0)
        return true ;
    return false ;
}

void SecretPoint::loadPublicKey(std::vector<unsigned char> data){
    secp256k1_context *context = OpenSSLContext::get_context();
    secp256k1_ec_pubkey_parse(context,&pubKey,data.data(),data.size());
}

CKey SecretPoint::loadPrivateKey(std::vector<unsigned char> data) {
    privKey.Set(data.begin(),data.end(),false);
}