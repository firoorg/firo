#ifndef ZCOIN_EXODUS_ENCODING_H
#define ZCOIN_EXODUS_ENCODING_H

#include "exodus.h"
#include "script.h"
#include "utils.h"

#include "../pubkey.h"
#include "../random.h"
#include "../utilstrencodings.h"

#include "../primitives/transaction.h"
#include "../script/script.h"
#include "../script/standard.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>

namespace exodus {

static_assert(CPubKey::COMPRESSED_PUBLIC_KEY_SIZE >= 4, "Size of compressed public key must be larger than 4 bytes");

constexpr unsigned CLASS_B_MAX_CHUNKS = 255;
constexpr unsigned CLASS_B_CHUNK_SIZE = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE - 2;
constexpr unsigned CLASS_B_CHUNK_PAYLOAD_SIZE = CLASS_B_CHUNK_SIZE - 1;

constexpr unsigned MAX_PAYLOAD = CLASS_B_CHUNK_PAYLOAD_SIZE * CLASS_B_MAX_CHUNKS;

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
            throw std::invalid_argument("key size is not valid");
        }

        std::copy(first, last, encKey.begin());
    }

public:
    template<typename Payload>
    CPubKey Encode(uint8_t chunk, Payload first, Payload last)
    {
        auto size = std::distance(first, last);

        if (size < 0 || static_cast<size_t>(size) > CLASS_B_CHUNK_PAYLOAD_SIZE) {
            throw std::invalid_argument("invalid payload");
        }

        std::array<unsigned char, CPubKey::COMPRESSED_PUBLIC_KEY_SIZE> data = {}; // Zeroes all bytes.

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

        throw std::runtime_error("could not generate a valid public key");
    }

protected:
    std::array<unsigned char, CLASS_B_CHUNK_SIZE> encKey;
};

/**
 * Embedds a payload in obfuscated multisig outputs, and adds an Exodus marker output.
 *
 * @see The class B transaction encoding specification:
 * https://github.com/mastercoin-MSC/spec#class-b-transactions-also-known-as-the-multisig-method
 */
template<typename Payload, typename Output>
Output EncodeClassB(const std::string& senderAddress, const CPubKey& redeemingKey, Payload first, Payload last, Output output)
{
    std::string packetKeys[MAX_SHA256_OBFUSCATION_TIMES + 1];
    auto remaining = std::distance(first, last);
    unsigned processed = 0;
    unsigned chunk = 1;

    PrepareObfuscatedHashes(senderAddress, MAX_SHA256_OBFUSCATION_TIMES, packetKeys);

     // FIXME: Remove MAX_SHA256_OBFUSCATION_TIMES definition.
    static_assert(MAX_SHA256_OBFUSCATION_TIMES == CLASS_B_MAX_CHUNKS, "Value of MAX_SHA256_OBFUSCATION_TIMES is not the same as chunk size");

    while (remaining > 0) {
        // Get number of keys required for payload.
        // At most 3 keys per output is allowed.
        int generatingKeys = (remaining > CLASS_B_CHUNK_PAYLOAD_SIZE) ? 2 : 1;

        // Put payload in the keys.
        std::vector<CPubKey> keys = { redeemingKey }; // Always include the redeeming pubkey

        for (int i = 0; i < generatingKeys; i++, chunk++) {
            // Get key to encrypt packet.
            if (chunk > CLASS_B_MAX_CHUNKS) {
                throw std::invalid_argument("payload too large");
            }

            auto packetKey = ParseHex(packetKeys[chunk]);

            assert(packetKey.size() >= CLASS_B_CHUNK_SIZE);

            packetKey.resize(CLASS_B_CHUNK_SIZE); // Truncate key to match with packet size.

            // Encode payload.
            KeyEncoder encoder(packetKey.begin(), packetKey.end());
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

    // Add the Exodus marker output
    auto script = GetScriptForDestination(ExodusAddress().Get());
    *output++ = CTxOut(GetDustThreshold(script), script);

    return output;
}

/**
 * Embedds a payload in an OP_RETURN output, prefixed with a transaction marker.
 *
 * The request is rejected, if the size of the payload with marker is larger than
 * the allowed data carrier size ("-datacarriersize=n").
 */
template<typename Payload>
CTxOut EncodeClassC(Payload first, Payload last)
{
    auto magic = GetExMarker();
    std::vector<unsigned char> data;
    CScript script;

    data.insert(data.end(), magic.begin(), magic.end());
    data.insert(data.end(), first, last);

    script << OP_RETURN << data;

    if (script.size() > nMaxDatacarrierBytes) {
        throw std::invalid_argument("packet too large");
    }

    return CTxOut(0, script);
}

} // namespace exodus

#endif // ZCOIN_EXODUS_ENCODING_H
