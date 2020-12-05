// Copyright (c) 2020 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_ELYSIUM_SIGNATUREBUILDER_H
#define FIRO_ELYSIUM_SIGNATUREBUILDER_H

#include "ecdsa_signature.h"

#include "../base58.h"
#include "../key.h"

namespace elysium {

class SignatureBuilder
{
public:
    virtual ECDSASignature Sign(CKey &key) const = 0;
    virtual bool Verify(CPubKey const &pubKey, ECDSASignature const &signature) const = 0;
};

class SigmaV1SignatureBuilder : SignatureBuilder
{
public:
    SigmaV1SignatureBuilder(
        CBitcoinAddress const &receiver,
        int64_t referenceAmount,
        SigmaProof const &proof);

public:
    ECDSASignature Sign(CKey &key) const;
    bool Verify(CPubKey const &pubKey, ECDSASignature const &signature) const;

protected:
    uint256 hash;
};

}

#endif // FIRO_ELYSIUM_SIGNATUREBUILDER_H