// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_ECDSA_SIGNATURE_H
#define ZCOIN_ELYSIUM_ECDSA_SIGNATURE_H

#include "ecdsa_context.h"

#include <secp256k1.h>

#include <array>
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
    ECDSASignature(unsigned char const *signature, size_t len);

public:
    std::vector<unsigned char> GetCompact() const;
    std::vector<unsigned char> GetDER() const;
    bool Valid() const;

    /** serialize as compact
     */
    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        if (!Valid()) {
            throw std::runtime_error("ECDSA Signature is invalid");
        }

        auto buffer = GetCompact();

        s.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    }

    /** unserialize compact
     */
    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        std::array<uint8_t, COMPACT_SIZE> buffer;
        s.read(reinterpret_cast<char*>(buffer.data()), sizeof(buffer));
        if (1 != secp256k1_ecdsa_signature_parse_compact(
            context.Get(),
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
    ECDSAContext context;
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_ECDSA_SIGNATURE_H