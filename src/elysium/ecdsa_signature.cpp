// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ecdsa_signature.h"

#include <stdexcept>

namespace elysium {

ECDSASignature::ECDSASignature() : valid(false)
{
}

ECDSASignature::ECDSASignature(secp256k1_ecdsa_signature const &sig)
    : signature(sig), valid(true)
{
}

ECDSASignature ECDSASignature::ParseCompact(ECDSAContext const &context, unsigned char const *signature)
{
    secp256k1_ecdsa_signature sig;

    if (1 != secp256k1_ecdsa_signature_parse_compact(
        context.Get(),
        &sig,
        signature)) {
        throw std::invalid_argument("Compact Signature is invalid");
    }

    return ECDSASignature(sig);
}

ECDSASignature ECDSASignature::ParseDER(ECDSAContext const &context, unsigned char const *signature, size_t len)
{
    secp256k1_ecdsa_signature sig;

    if (1 != secp256k1_ecdsa_signature_parse_der(
        context.Get(),
        &sig,
        signature,
        len)) {
        throw std::invalid_argument("DER Signature is invalid");
    }

    return ECDSASignature(sig);
}

std::vector<unsigned char> ECDSASignature::GetCompact(ECDSAContext const &context) const
{
    if (!Valid()) {
        throw std::logic_error("Signature is invalid.");
    }

    std::vector<unsigned char> result;
    result.resize(COMPACT_SIZE);

    if (1 != secp256k1_ecdsa_signature_serialize_compact(
        context.Get(),
        result.data(),
        &signature)) {
        throw std::runtime_error("Serialized size is in valid");
    }

    return result;
}

std::vector<unsigned char> ECDSASignature::GetDER(ECDSAContext const &context) const
{
    if (!Valid()) {
        throw std::logic_error("Signature is invalid.");
    }

    std::vector<unsigned char> result;
    result.resize(DER_SIZE);

    size_t outLen = DER_SIZE;
    if (1 != secp256k1_ecdsa_signature_serialize_der(
        context.Get(),
        result.data(),
        &outLen,
        &signature)) {
        throw std::runtime_error("Serialized size is in valid");
    }

    return result;
}

bool ECDSASignature::Valid() const
{
    return valid;
}

} // namespace elysium