#ifndef ZCOIN_ELYSIUM_PACKETENCODER_H
#define ZCOIN_ELYSIUM_PACKETENCODER_H

#include "script.h"

#include "../base58.h"
#include "../pubkey.h"
#include "../random.h"

#include "../primitives/transaction.h"

#include "../script/script.h"
#include "../script/standard.h"

#include <boost/optional.hpp>

#include <algorithm>
#include <array>
#include <iterator>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <inttypes.h>
#include <stddef.h>

namespace exodus {

static_assert(CPubKey::COMPRESSED_PUBLIC_KEY_SIZE >= 4, "Size of compressed public key must be at least 4 bytes");

constexpr unsigned CLASS_B_MAX_CHUNKS = 255;
constexpr unsigned CLASS_B_CHUNK_SIZE = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE - 2; // One byte require for key type, another for ECDSA coordinate fix.
constexpr unsigned CLASS_B_CHUNK_PAYLOAD_SIZE = CLASS_B_CHUNK_SIZE - 1; // One byte for chunk number.

/**
 * Maximum size for packet payload for all classes.
 **/
constexpr unsigned MAX_PACKET_PAYLOAD = CLASS_B_CHUNK_PAYLOAD_SIZE * CLASS_B_MAX_CHUNKS;

enum class PacketClass
{
    B,
    C
};

class PacketKeyGenerator
{
public:
    PacketKeyGenerator(const std::string& seed);

public:
    std::array<unsigned char, 32> Next();

protected:
    std::string seed;
};

class KeyEncoder
{
public:
    template<typename PacketKey>
    KeyEncoder(PacketKey first, PacketKey last)
    {
        SetPacketKey(first, last);
    }

public:
    template<typename PacketKey>
    void SetPacketKey(PacketKey first, PacketKey last)
    {
        auto size = std::distance(first, last);

        if (size < 0 || static_cast<size_t>(size) != encKey.size()) {
            throw std::invalid_argument("Invalid key size");
        }

        std::copy(first, last, encKey.begin());
    }

public:
    template<typename Payload>
    CPubKey Encode(uint8_t chunk, Payload first, Payload last)
    {
        auto size = std::distance(first, last);

        if (size < 0 || static_cast<size_t>(size) > CLASS_B_CHUNK_PAYLOAD_SIZE) {
            throw std::invalid_argument("Invalid payload");
        }

        std::array<unsigned char, CPubKey::COMPRESSED_PUBLIC_KEY_SIZE> data;
        data.fill(0);

        // Write chunk number and payload.
        static_assert(CLASS_B_CHUNK_SIZE + 2 == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE, "Chunk size is not in the expected size");
        static_assert(CLASS_B_CHUNK_PAYLOAD_SIZE + 1 == CLASS_B_CHUNK_SIZE, "Payload size is not in the expected size");

        data[0] = 0x02; // Compressed public key indicator.
        data[1] = chunk;

        std::copy(first, last, data.begin() + 2);

        // Obfuscation packet, which is chunk number and payload.
        static_assert(std::tuple_size<decltype(encKey)>::value == CLASS_B_CHUNK_SIZE, "Size of encryption key must be the same as chunk size");

        auto it = data.begin() + 1;

        for (unsigned i = 0; i < CLASS_B_CHUNK_SIZE; i++) {
            *it++ ^= encKey[i];
        }

        // Fix ECDSA coodinate.
        auto fix = static_cast<unsigned char>(GetRand(256));

        for (int i = 0; i < 256; i++, fix++) {
            *it = fix;

            CPubKey key(data.begin(), data.end());
            if (key.IsFullyValid()) {
                return key;
            }
        }

        throw std::runtime_error("Failed to generate a valid public key");
    }

protected:
    std::array<unsigned char, CLASS_B_CHUNK_SIZE> encKey;
};

/**
 * Prefix of class C packet.
 **/
extern const std::array<unsigned char, 6> magic;

const CBitcoinAddress& GetSystemAddress();
boost::optional<PacketClass> DeterminePacketClass(const CTransaction& tx, int height);

/**
 * Embedds a payload in obfuscated multisig outputs, then adds P2PKH output to system address.
 *
 * @see The class B transaction encoding specification: https://github.com/mastercoin-MSC/spec#class-b-transactions-also-known-as-the-multisig-method
 **/
template<typename Payload, typename Output>
Output EncodeClassB(const std::string& sender, const CPubKey& redeemingKey, Payload first, Payload last, Output output)
{
    auto remaining = std::distance(first, last);
    PacketKeyGenerator packetKeys(sender);
    size_t processed = 0;
    unsigned chunk = 1;

    while (remaining > 0) {
        // Get number of keys required for payload.
        // At most 3 keys per output is allowed.
        int generatingKeys = (remaining > static_cast<signed>(CLASS_B_CHUNK_PAYLOAD_SIZE)) ? 2 : 1;

        // Put payload in the keys.
        std::vector<CPubKey> keys = { redeemingKey }; // Always include the redeeming pubkey

        for (int i = 0; i < generatingKeys; i++, chunk++) {
            if (chunk > CLASS_B_MAX_CHUNKS) {
                throw std::invalid_argument("Payload too large");
            }

            // Get key to encrypt packet.
            auto packetKey = packetKeys.Next();

            static_assert(std::tuple_size<decltype(packetKey)>::value >= CLASS_B_CHUNK_SIZE, "Size of packet key is less than packet size");

            // Encode payload.
            KeyEncoder encoder(packetKey.begin(), packetKey.end() - (packetKey.size() - CLASS_B_CHUNK_SIZE));
            auto selected = std::min(remaining, static_cast<decltype(remaining)>(CLASS_B_CHUNK_PAYLOAD_SIZE));

            auto encoded = encoder.Encode(static_cast<uint8_t>(chunk), first + processed, first + processed + selected);
            keys.push_back(std::move(encoded));

            processed += selected;
            remaining -= selected;
        }

        // Create output.
        auto script = GetScriptForMultisig(1, keys);
        *output++ = CTxOut(GetDustThreshold(script), script);
    }

    // Add P2PKH output to system address.
    auto script = GetScriptForDestination(GetSystemAddress().Get());
    *output++ = CTxOut(GetDustThreshold(script), script);

    return output;
}

/**
 * Embedds a payload in an OP_RETURN output, prefixed with magic bytes.
 **/
template<typename Payload>
CTxOut EncodeClassC(Payload first, Payload last)
{
    std::vector<unsigned char> data;
    CScript script;

    data.insert(data.end(), magic.begin(), magic.end());
    data.insert(data.end(), first, last);

    script << OP_RETURN << data;

    if (script.size() > nMaxDatacarrierBytes) {
        throw std::invalid_argument("Payload is too large");
    }

    return CTxOut(0, script);
}

} // namespace exodus

namespace std {

using namespace exodus;

string to_string(PacketClass c);

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, PacketClass v)
{
    return os << to_string(v);
}

} // namespace std

#endif // ZCOIN_ELYSIUM_PACKETENCODER_H
