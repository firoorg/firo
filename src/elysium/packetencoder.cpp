#include "packetencoder.h"

#include "rules.h"
#include "script.h"
#include "utilsbitcoin.h"

#include "../base58.h"
#include "../utilstrencodings.h"

#include "../crypto/sha256.h"

#include "../script/standard.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include <ctype.h>

namespace elysium {

// could not change to "elysium" because of previous exodus transactions
const std::array<unsigned char, 6> magic = { 0x65, 0x78, 0x6f, 0x64, 0x75, 0x73 }; // "exodus"

// PacketKeyGenerator Implementation.

PacketKeyGenerator::PacketKeyGenerator(const std::string& seed) : seed(seed)
{
}

std::array<unsigned char, 32> PacketKeyGenerator::Next()
{
    CSHA256 hasher;
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash;

    hasher.Write(reinterpret_cast<const unsigned char *>(seed.data()), seed.size());
    hasher.Finalize(hash.data());

    seed = HexStr(hash.begin(), hash.end());
    std::transform(seed.begin(), seed.end(), seed.begin(), ::toupper);

    return hash;
}

// Functions.

const CBitcoinAddress& GetSystemAddress()
{
    static const CBitcoinAddress mainAddress("ZzzcQkPmXomcTcSVGsDHsGBCvxg67joaj5");
    static const CBitcoinAddress testAddress("TTFL4sPFHP22Dzqbw9mPQJEjdG7Wf1ajjZ");

    return isNonMainNet() ? testAddress : mainAddress;
}

boost::optional<PacketClass> DeterminePacketClass(const CTransaction& tx, int height)
{
    // Inspect all outputs.
    auto& sysAddr = GetSystemAddress();
    bool hasSysAddr = false;
    bool hasMultisig = false;
    bool hasOpReturn = false;

    for (auto& output : tx.vout) {
        txnouttype type;

        if (!GetOutputType(output.scriptPubKey, type)) {
            continue;
        }

        if (!IsAllowedOutputType(type, height)) {
            continue;
        }

        if (type == TX_PUBKEYHASH) {
            CTxDestination dest;

            if (ExtractDestination(output.scriptPubKey, dest) && CBitcoinAddress(dest) == sysAddr) {
                hasSysAddr = true;
            }
        } else if (type == TX_MULTISIG) {
            hasMultisig = true;
        } else if (type == TX_NULL_DATA) {
            // Check if the first push is prefixed with magic bytes.
            std::vector<std::vector<unsigned char>> pushes;

            GetPushedValues(output.scriptPubKey, std::back_inserter(pushes));

            if (!pushes.empty() && pushes[0].size() >= magic.size() && std::equal(magic.begin(), magic.end(), pushes[0].begin())) {
                hasOpReturn = true;
            }
        }
    }

    // Determine packet class based on inspection result.
    if (hasOpReturn) {
        return PacketClass::C;
    }

    if (hasSysAddr && hasMultisig) {
        return PacketClass::B;
    }

    return boost::none;
}

} // namespace elysium

namespace std {

using namespace elysium;

string to_string(PacketClass c)
{
    switch (c) {
    case PacketClass::B:
        return "B";
    case PacketClass::C:
        return "C";
    default:
        throw invalid_argument("Packet class is not valid");
    }
}

} // namespace std
