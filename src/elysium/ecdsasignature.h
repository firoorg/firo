#ifndef ZCOIN_ELYSIUM_ECDSASIGNATURE_H
#define ZCOIN_ELYSIUM_ECDSASIGNATURE_H

#include "../sigma/openssl_context.h"

#include <secp256k1.h>

#include <array>
#include <vector>

namespace elysium {

class ECDSASignature
{
public:
    static size_t const SIGNATURE_DER_SERIALIZED_SIZE = 72;

private:
    secp256k1_ecdsa_signature signature;
    bool valid;

public:
    ECDSASignature();
    ECDSASignature(unsigned char const *signature, size_t len);

public:
    bool Valid() const;
    std::vector<unsigned char> Data() const;

    /** serialize as compact
     */
    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        if (!Valid()) {
            throw std::runtime_error("ECDSA Signature is invalid");
        }

        std::array<uint8_t, 64> buffer;
        secp256k1_ecdsa_signature_serialize_compact(
            Context(),
            reinterpret_cast<unsigned char*>(buffer.begin()),
            &signature);

        s.write(reinterpret_cast<char*>(buffer.begin()), sizeof(buffer));
    }

    /** unserialize compact
     */
    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        valid = false;
        std::array<uint8_t, 64> buffer;
        s.read(reinterpret_cast<char*>(buffer.begin()), sizeof(buffer));
        if (1 != secp256k1_ecdsa_signature_parse_compact(
            Context(),
            &signature,
            reinterpret_cast<const unsigned char*>(buffer.begin()))) {
            throw std::runtime_error("Fail to parse compacted serialized data");
        }

        valid = true;
    }

private:
    static secp256k1_context *Context() 
    {
        return OpenSSLContext::get_context();
    }
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_ECDSASIGNATURE_H