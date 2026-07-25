// Copyright (c) 2026 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_SPARKMESSAGE_H
#define FIRO_SPARK_SPARKMESSAGE_H

#include <string>

#include "../libspark/keys.h"

namespace spark {

/*
 * Message signing and verification for Spark addresses.
 *
 * A signature is a libspark OwnershipProof over the message digest, serialized and hex
 * encoded. The RPC layer and the GUI both go through here, so the digest convention lives
 * in one place. The signing half needs a wallet and lives in CSparkWallet::SignMessage.
 */

// Message digest as a Scalar, the value an ownership proof commits to. Hashed the same way
// as signmessage: strMessageMagic followed by the message.
Scalar MessageScalar(const std::string& message);

enum class VerifyResult
{
    Ok,             // proof is valid for this address and message
    Mismatch,       // well formed proof, but not valid for this address and message
    InvalidAddress, // address could not be decoded
    WrongNetwork,   // address decoded but belongs to a different network
    NotHex,         // signature is not a hex string
    MalformedProof  // signature is hex but does not deserialize to an OwnershipProof
};

// Verify a hex encoded OwnershipProof against an encoded Spark address. Never throws.
VerifyResult VerifyMessage(const std::string& encodedAddress,
                           const std::string& hexProof,
                           const std::string& message);

} // namespace spark

#endif // FIRO_SPARK_SPARKMESSAGE_H
