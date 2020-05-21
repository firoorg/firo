// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_ECDSA_SIGNATURE_H
#define ZCOIN_ELYSIUM_ECDSA_SIGNATURE_H

#include "ecdsa_context.h"

#include <secp256k1.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace elysium {

class ECDSASignature
{
public:
    static size_t constexpr DER_SIZE = 72;
    static size_t constexpr COMPACT_SIZE = 64;

public:
    ECDSASignature();
    ECDSASignature(secp256k1_ecdsa_signature const &sig);

public:
    static ECDSASignature Parse(ECDSAContext const &context, unsigned char const *signature, size_t len);

public:
    std::vector<unsigned char> GetCompact(ECDSAContext const &context) const;
    std::vector<unsigned char> GetDER(ECDSAContext const &context) const;
    bool Valid() const;

    /** serialize as compact
     */
    template<typename Stream>
    void Serialize(Stream& s) const
    {
        if (!Valid()) {
            throw std::logic_error("ECDSA Signature is invalid");
        }

        auto buffer = GetCompact(ECDSAContext::CreateSignContext());

        s.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    }

    /** unserialize compact
     */
    template<typename Stream>
    void Unserialize(Stream& s)
    {
        std::array<uint8_t, COMPACT_SIZE> buffer;
        s.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        if (1 != secp256k1_ecdsa_signature_parse_compact(
            ECDSAContext::CreateVerifyContext().Get(),
            &signature,
            reinterpret_cast<const unsigned char*>(buffer.data()))) {
            valid = false;
            throw std::runtime_error("Fail to parse compacted serialized data");
        }

        valid = true;
    }

private:
    secp256k1_ecdsa_signature signature;
    bool valid;
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_ECDSA_SIGNATURE_H