// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../libzerocoin/Zerocoin.h"
#include "../sigma/openssl_context.h"

#include "base58.h"

#include <secp256k1/include/Scalar.h>

#include "convert.h"
#include "coinsigner.h"
#include "sigmaprimitives.h"
#include "signaturebuilder.h"

namespace exodus {

SigmaV1SignatureBuilder::SigmaV1SignatureBuilder(
    CBitcoinAddress const &receiver,
    int64_t referenceAmount,
    SigmaProof const &proof,
    unsigned char const *publicKey,
    size_t publicKeySize)
{
    // serialize payload
    CKeyID keyId;
    if (!receiver.GetKeyID(keyId)) {
        throw std::runtime_error("Fail to get address key id.");
    }

    payload.insert(payload.end(), keyId.begin(), keyId.end());

    // reference amount
    exodus::swapByteOrder(referenceAmount);
    payload.insert(
        payload.end(),
        reinterpret_cast<unsigned char*>(referenceAmount),
        reinterpret_cast<unsigned char*>(referenceAmount) + sizeof(referenceAmount));

    // serial and proof
    unsigned char *ptr = &payload.back();
    payload.resize(payload.size() +
        sizeof(proof.serial.memoryRequired()) +
        sizeof(proof.proof.memoryRequired()));

    ptr = proof.serial.serialize(ptr);
    ptr = proof.proof.serialize(ptr);

    // copy public key
    if (publicKeySize != sizeof(this->publicKey)) {
        throw std::runtime_error("Public key size is invalid.");
    }

    std::copy(publicKey, publicKey + publicKeySize, this->publicKey.data());
}

std::array<uint8_t, 64> SigmaV1SignatureBuilder::Sign(CoinSigner &signer)
{
    signer.Write(reinterpret_cast<const char*>(payload.data()), payload.size());
    return signer.GetSignature();
}

bool SigmaV1SignatureBuilder::Verify(std::array<uint8_t, 64> const &signature)
{
    std::array<uint8_t, 32> hash;
    CSHA256().Write(payload.data(), payload.size()).Finalize(hash.data());

    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature parsedSignature;

    if (1 != secp256k1_ec_pubkey_parse(
        OpenSSLContext::get_context(),
        &pubkey,
        this->publicKey.data(),
        this->publicKey.size())) {
        throw std::runtime_error("Sigma spend failed due to unable to parse public key");
    }

    if (1 != secp256k1_ecdsa_signature_parse_compact(
        OpenSSLContext::get_context(),
        &parsedSignature,
        signature.data())) {
        throw std::runtime_error("Sigma spend fail due to unable to parse signature");
    }

    return 1 == secp256k1_ecdsa_verify(OpenSSLContext::get_context(), &parsedSignature, hash.data(), &pubkey);
}

}