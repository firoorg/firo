// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coinsigner.h"

namespace elysium {

CoinSigner::CoinSigner(CKey const &priv)
    : key(priv), context(ECDSAContext::CreateSignContext())
{
}

CPubKey CoinSigner::GetPublicKey() const
{
    secp256k1_pubkey pubkey;
    if(!secp256k1_ec_pubkey_create(
        context.Get(), &pubkey, key.begin())) {
        throw std::runtime_error("Unable to get public key.");
    }

    CPubKey result;
    size_t len = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE;
    if (1 != secp256k1_ec_pubkey_serialize(
        context.Get(),
        (unsigned char*)result.begin(), &len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        throw std::runtime_error("Unable to serialize public key");
    }

    if (result.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) {
        throw std::runtime_error("Pubkey size is not equal to compressed");
    }

    if (!result.IsValid()) {
        throw std::runtime_error("Public key is invalid");
    }

    return result;
}

Signature CoinSigner::Sign(unsigned char const *start, unsigned char const *end)
{
    if (std::distance(start, end) != 32) {
        throw std::runtime_error("Payload to sign is invalid.");
    }

    uint256 hash;
    std::copy(start, end, hash.begin());

    std::vector<unsigned char> sig;
    key.Sign(hash, sig);

    return Signature(sig.data(), sig.size());
}

} // namespace elysium