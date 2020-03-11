// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "signature.h"

#include <stdexcept>

namespace elysium {

Signature::Signature() : valid(false), context(ECDSAContext::CreateSignContext())
{
}

Signature::Signature(secp256k1_ecdsa_signature const &sig)
    : signature(sig), valid(true), context(ECDSAContext::CreateSignContext())
{
}

Signature::Signature(unsigned char const *signature, size_t len)
    : valid(false), context(ECDSAContext::CreateSignContext())
{
    if (len >= 70 && len <= 72) {
        if (1 == secp256k1_ecdsa_signature_parse_der(
            context.Get(),
            &(this->signature),
            signature,
            len))
        {
            valid = true;
        }
    } else if (len == SIGNATURE_COMPACT_SERIALIZED_SIZE) {
        if (1 == secp256k1_ecdsa_signature_parse_compact(
            context.Get(),
            &(this->signature),
            signature)) {
            valid = true;
        }
    } else {
        throw std::invalid_argument("Signature encoding type is not supported");
    }
}

std::vector<unsigned char> Signature::GetCompact() const
{
    std::vector<unsigned char> result;
    result.resize(SIGNATURE_COMPACT_SERIALIZED_SIZE);

    if (1 != secp256k1_ecdsa_signature_serialize_compact(
        context.Get(),
        result.data(),
        &signature)) {
        throw std::runtime_error("Serialized size is in valid");
    }

    return result;
}

std::vector<unsigned char> Signature::GetDER() const
{
    std::vector<unsigned char> result;
    result.resize(SIGNATURE_DER_SERIALIZED_SIZE);

    size_t outLen = SIGNATURE_DER_SERIALIZED_SIZE;
    if (1 != secp256k1_ecdsa_signature_serialize_der(
        context.Get(),
        result.data(),
        &outLen,
        &signature)) {
        throw std::runtime_error("Serialized size is in valid");
    }

    return result;
}

bool Signature::Valid() const
{
    return valid;
}

} // namespace elysium