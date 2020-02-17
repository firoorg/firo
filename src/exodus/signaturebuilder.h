// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_SIGNATUREBUILDER_H
#define ZCOIN_EXODUS_SIGNATUREBUILDER_H

#include "base58.h"
#include "coinsigner.h"

#include <secp256k1/include/Scalar.h>

#include "sigmaprimitives.h"

namespace exodus {

class SignatureBuilder
{
public:
    virtual std::array<uint8_t, 64> Sign(CoinSigner &signer) = 0;
    virtual bool Verify(std::array<uint8_t, 64> const &signature) = 0;
};

class SigmaV1SignatureBuilder : SignatureBuilder
{
protected:
    CHashWriter hasher;
    std::array<uint8_t, 33> publicKey;

public:
    SigmaV1SignatureBuilder(
        CBitcoinAddress const &receiver,
        int64_t referenceAmount,
        SigmaProof const &proof,
        unsigned char const *publicKey,
        size_t publicKeySize);

public:
    std::array<uint8_t, 64> Sign(CoinSigner &signer);
    bool Verify(std::array<uint8_t, 64> const &signature);

    std::array<uint8_t, 33> const& PublicKey();
};

}

#endif // ZCOIN_EXODUS_SIGNATUREBUILDER_H