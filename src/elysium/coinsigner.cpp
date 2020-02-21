// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coinsigner.h"

#include "../libzerocoin/Zerocoin.h"
#include "../sigma/openssl_context.h"

namespace elysium {

CoinSigner::CoinSigner(ECDSAPrivateKey priv)
    : key(priv)
{
}

ECDSAPublicKey CoinSigner::GetPublicKey() const
{
    secp256k1_pubkey pubkey;
    if(!secp256k1_ec_pubkey_create(
        OpenSSLContext::get_context(), &pubkey, key.begin())) {
        throw std::runtime_error("Unable to get public key.");
    }

    ECDSAPublicKey compressedPubKey;
    size_t len = sizeof(compressedPubKey);
    if (1 != secp256k1_ec_pubkey_serialize(
        OpenSSLContext::get_context(),
        compressedPubKey.begin(), &len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        throw std::runtime_error("Unable to serialize public key");
    }

    return compressedPubKey;
}

ECDSASignature CoinSigner::Sign(unsigned char const *start, unsigned char const *end)
{
    if (std::distance(start, end) != 32) {
        throw std::runtime_error("Payload to sign is invalid.");
    }

    secp256k1_ecdsa_signature sig;
    if (1 != secp256k1_ecdsa_sign(
        OpenSSLContext::get_context(),
        &sig,
        start,
        key.begin(),
        nullptr,
        nullptr)) {
        throw std::runtime_error("Unable to sign with ECDSA key.");
    }

    ECDSASignature serializedSig;
    if (1 != secp256k1_ecdsa_signature_serialize_compact(
        OpenSSLContext::get_context(), serializedSig.data(), &sig)) {
        throw std::runtime_error("Unable to serialize ecdsa signature.");
    }

    return serializedSig;
}

} // namespace elysium