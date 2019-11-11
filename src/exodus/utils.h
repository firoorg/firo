#ifndef EXODUS_UTILS_H
#define EXODUS_UTILS_H

#include <string>

#include "uint256.h"

/** Determines the Bitcoin address associated with a given hash and version. */
std::string HashToAddress(unsigned char version, const uint160& hash);

/** Returns a vector of bytes containing the version and hash160 for an address.*/
std::vector<unsigned char> AddressToBytes(const std::string& address);

#endif // EXODUS_UTILS_H
