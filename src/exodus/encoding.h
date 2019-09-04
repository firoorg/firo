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
#include <vector>

#include <stddef.h>

namespace exodus {

constexpr unsigned MAX_PAYLOAD_PER_KEY = 30;

template<typename Packet>
CPubKey EncodeMultiSigKey(unsigned char sequence, const std::vector<unsigned char>& encKey, Packet begin, Packet end)
{
    if (encKey.size() != 32) {
        throw std::invalid_argument("invalid encryption key");
    }

    if (std::distance(begin, end) > MAX_PAYLOAD_PER_KEY) {
        throw std::invalid_argument("packet too large");
    }

    std::array<unsigned char, 33> data = {}; // Zeroes all bytes.

    // Write sequence and payload.
    data[0] = 0x02; // Public key prefix.
    data[1] = sequence;
    std::copy(begin, end, data.begin() + 2);

    // Obfuscation sequence and payload.
    for (int i = 1; i < 32; i++) {
        data[i] ^= encKey[i - 1];
    }

    // Fix ECDSA coodinate.
    auto fix = static_cast<unsigned char>(GetRand(256));

    for (int i = 0; i < 256; i++, fix++) {
        data[32] = fix;

        CPubKey key(data.begin(), data.end());
        if (key.IsFullyValid()) {
            return key;
        }
    }

    throw std::runtime_error("could not generate a valid public key");
}

/**
 * Embedds a payload in obfuscated multisig outputs, and adds an Exodus marker output.
 *
 * @see The class B transaction encoding specification:
 * https://github.com/mastercoin-MSC/spec#class-b-transactions-also-known-as-the-multisig-method
 */
template<typename Packet, typename Output>
Output EncodeClassB(const std::string& senderAddress, const CPubKey& redeemingKey, Packet begin, Packet end, Output output)
{
    std::string obfuscatedHashes[MAX_SHA256_OBFUSCATION_TIMES + 1];
    auto remaining = std::distance(begin, end);
    unsigned processed = 0;
    unsigned sequence = 1;

    PrepareObfuscatedHashes(senderAddress, MAX_SHA256_OBFUSCATION_TIMES, obfuscatedHashes);

    while (remaining > 0) {
        // Get number of keys required for payload.
        // At most 3 keys per output is allowed.
        int generatingKeys = (remaining > MAX_PAYLOAD_PER_KEY) ? 2 : 1;

        // Put packet in the keys.
        std::vector<CPubKey> keys = { redeemingKey }; // Always include the redeeming pubkey

        for (int i = 0; i < generatingKeys; i++, sequence++) {
            if (sequence >= (MAX_SHA256_OBFUSCATION_TIMES + 1)) {
                throw std::runtime_error("packet too large");
            }

            auto selected = std::min(remaining, static_cast<decltype(remaining)>(MAX_PAYLOAD_PER_KEY));

            auto key = EncodeMultiSigKey(
                static_cast<unsigned char>(sequence),
                ParseHex(obfuscatedHashes[sequence]),
                begin + processed,
                begin + processed + selected
            );

            processed += selected;
            remaining -= selected;

            keys.push_back(key);
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
template<typename Packet>
CTxOut EncodeClassC(Packet begin, Packet end)
{
    auto magic = GetExMarker();
    std::vector<unsigned char> data;
    CScript script;

    data.insert(data.end(), magic.begin(), magic.end());
    data.insert(data.end(), begin, end);

    script << OP_RETURN << data;

    if (script.size() > nMaxDatacarrierBytes) {
        throw std::invalid_argument("packet too large");
    }

    return CTxOut(0, script);
}

} // namespace exodus

#endif // ZCOIN_EXODUS_ENCODING_H
