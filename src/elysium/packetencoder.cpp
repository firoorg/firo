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

const std::array<unsigned char, 7> magic = { 0x65, 0x6c, 0x79, 0x73, 0x69, 0x75, 0x6d }; // "elysium"

// Functions.


const CBitcoinAddress& GetSystemAddress()
{
    static const CBitcoinAddress mainAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U");
    static const CBitcoinAddress testAddress("TKPbcG9QVLSfNvrtowQ7GzEEXq4zPjkej6");

    return isNonMainNet() ? testAddress : mainAddress;
}

boost::optional<PacketClass> DeterminePacketClass(const CTransaction& tx, int height)
{
    for (auto& output : tx.vout) {
        if (output.scriptPubKey.IsElysium()) return PacketClass::C;
    }

    return boost::none;
}

} // namespace elysium

namespace std {

using namespace elysium;

string to_string(PacketClass c)
{
    switch (c) {
    case PacketClass::C:
        return "C";
    default:
        throw invalid_argument("Packet class is not valid");
    }
}

} // namespace std
