#include "sigma/coin.h"
#include "SecretPoint.h"

SecretPoint::SecretPoint() {
}

SecretPoint::SecretPoint(std::vector<unsigned char> dataPrv, std::vector<unsigned char> dataPub)
{
    loadPrivateKey(dataPrv);
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

bool SecretPoint::isShared(SecretPoint secret) {
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

bool SecretPoint::equals(SecretPoint &v_secret){
    string str1 = HexStr(ECDHSecretAsBytes());
    string str2 = HexStr(v_secret.ECDHSecretAsBytes());
    if(str1.compare(str2)==0)
        return true ;
    return false ;
}

void SecretPoint::loadPublicKey(std::vector<unsigned char> data) {
    secp256k1_context *context = OpenSSLContext::get_context();
    secp256k1_ec_pubkey_parse(context,&pubKey,data.data(),data.size());
}

void SecretPoint::loadPrivateKey(std::vector<unsigned char> data) {
    privKey.Set(data.begin(),data.end(),false);
}

bool SecretPoint::SelfTest(CWallet* wallet)
{
    CKey key1, key2;
    
    
    CPubKey pubkey1, pubkey2;

    std::vector<unsigned char> pubkeyPcode =
    ParseHex("03c5f5da29143d68b2415bf9214bc8dcfe059c640f416deb7ba4021e3b33857237");
    std::vector<unsigned char> scriptSigPub =
    ParseHex("02b6d7f89a01b9b3bf0bb45c24cee0127586578869b1c43968ad311158eb7e2e40");
    
    std::vector<unsigned char> designatedKey =
    ParseHex("32e4b85b7efe7e91e6cee5d1ae7cda2b61cd5fa7c09a6afe107b277183864daa");
    std::vector<unsigned char> pcodeKey = ParseHex("72968cda4d199f3e4899c483523241fc1f8844f24b2d0c4b24a0bfaf1a1ef64e");
    
    pubkey1.Set(pubkeyPcode.begin(), pubkeyPcode.end());
    pubkey2.Set(scriptSigPub.begin(), scriptSigPub.end());



    std::vector<unsigned char> key1bytes(key1.begin(), key1.end());
    std::vector<unsigned char> key2bytes(key2.begin(), key2.end());
    
    std::vector<unsigned char> pubkey1bytes(pubkey1.begin(), pubkey1.end());
    std::vector<unsigned char> pubkey2bytes(pubkey2.begin(), pubkey2.end());
    
    SecretPoint scretp1(key1bytes, pubkey2bytes);
    SecretPoint scretp2(key2bytes, pubkey1bytes);
    return scretp1.equals(scretp2);
}

