// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "convert.h"
#include "sigmaprimitives.h"
#include "signaturebuilder.h"

#include "../base58.h"

namespace elysium {

SigmaV1SignatureBuilder::SigmaV1SignatureBuilder(
    CBitcoinAddress const &receiver,
    int64_t referenceAmount,
    SigmaProof const &proof)
{
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);

    // serialize payload
    uint160 keyId;
    AddressType type;
    if (!receiver.GetIndexKey(keyId, type)) {
        throw std::runtime_error("Fail to get address key id.");
    }

    hasher.write(reinterpret_cast<char*>(keyId.begin()), keyId.size());

    // reference amount
    elysium::swapByteOrder(referenceAmount);
    hasher.write(reinterpret_cast<char*>(&referenceAmount), sizeof(referenceAmount));

    // serial and proof
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;
    std::vector<char> serializedData;
    serializedData.insert(serializedData.end(), serialized.begin(), serialized.end());

    hasher.write(serializedData.data(), serializedData.size());

    hash = hasher.GetHash();
}

ECDSASignature SigmaV1SignatureBuilder::Sign(CKey &key) const
{
    std::vector<unsigned char> sig;
    if (!key.Sign(hash, sig)) {
        throw std::runtime_error("Fail to sign payload");
    }

    return ECDSASignature(ECDSAContext::CreateSignContext(), sig.data(), sig.size());
}

bool SigmaV1SignatureBuilder::Verify(CPubKey const &pubKey, ECDSASignature const &signature) const
{
    return pubKey.Verify(hash, signature.GetDER(ECDSAContext::CreateVerifyContext()));
}

}