// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_COINSIGNER_H
#define ZCOIN_EXODUS_COINSIGNER_H

#include "hash.h"

#include "../libzerocoin/Zerocoin.h"
#include "../sigma/openssl_context.h"

namespace exodus {

class CoinSigner
{
public:
    CoinSigner(unsigned char const *ecdsaKey, size_t keySize);

protected:
    std::array<uint8_t, 32> key;
    CHashWriter hasher;

public:
    std::array<uint8_t, 33> GetPublicKey() const;

    template<class It>
    std::array<uint8_t, 64> Sign(It start, It end)
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

        std::array<uint8_t, 64> serializedSig;
        if (1 != secp256k1_ecdsa_signature_serialize_compact(
            OpenSSLContext::get_context(), serializedSig.data(), &sig)) {
            throw std::runtime_error("Unable to serialize ecdsa signature.");
        }

        return serializedSig;
    }
};

}

#endif // ZCOIN_EXODUS_WALLET_H