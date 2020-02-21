/**
 * @file utils.cpp
 *
 * This file serves to seperate utility functions from the main exodus.cpp
 * and exodus.h files.
 */

#include "elysium/utils.h"

#include "base58.h"
#include "utilstrencodings.h"

// TODO: use crypto/sha256 instead of openssl
#include "openssl/sha.h"

#include "elysium/log.h"
#include "elysium/script.h"

#include <boost/algorithm/string.hpp>

#include <assert.h>
#include <string.h>
#include <string>
#include <vector>

std::string HashToAddress(unsigned char version, const uint160& hash)
{
    CBitcoinAddress address;
    if (version == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS)[0]) {
        CKeyID keyId = hash;
        address.Set(keyId);
        return address.ToString();
    } else if (version == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS)[0]) {
        CScriptID scriptId = hash;
        address.Set(scriptId);
        return address.ToString();
    }

    return "";
}

std::vector<unsigned char> AddressToBytes(const std::string& address)
{
    std::vector<unsigned char> addressBytes;
    bool success = DecodeBase58(address, addressBytes);
    if (!success) {
        PrintToLog("ERROR: failed to decode address %s.\n", address);
    }
    if (addressBytes.size() == 25) {
        addressBytes.resize(21); // truncate checksum
    } else {
        PrintToLog("ERROR: unexpected size from DecodeBase58 when decoding address %s.\n", address);
    }

    return addressBytes;
}
