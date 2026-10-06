// Copyright (c) 2026 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sparkmessage.h"

#include "state.h"
#include "../hash.h"
#include "../streams.h"
#include "../utilstrencodings.h"
#include "../validation.h" // For strMessageMagic
#include "../version.h"

namespace spark {

Scalar MessageScalar(const std::string& message)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << message;

    Scalar m;
    m.SetHex(ss.GetHash().GetHex());
    return m;
}

VerifyResult VerifyMessage(const std::string& encodedAddress,
                           const std::string& hexProof,
                           const std::string& message)
{
    const spark::Params* params = spark::Params::get_default();
    spark::Address address(params);
    unsigned char coinNetwork;
    try {
        coinNetwork = address.decode(encodedAddress);
    } catch (const std::exception&) {
        return VerifyResult::InvalidAddress;
    }
    if (coinNetwork != GetNetworkType())
        return VerifyResult::WrongNetwork;

    if (!IsHex(hexProof))
        return VerifyResult::NotHex;

    std::vector<unsigned char> proofData = ParseHex(hexProof);
    CDataStream proofStream(proofData, SER_NETWORK, PROTOCOL_VERSION);
    spark::OwnershipProof proof;
    try {
        proofStream >> proof;
    } catch (const std::exception&) {
        return VerifyResult::MalformedProof;
    }

    // Require the exact canonical encoding emitted by the serializers.
    CDataStream canonicalProof(SER_NETWORK, PROTOCOL_VERSION);
    canonicalProof << proof;
    if (proofData != std::vector<unsigned char>(canonicalProof.begin(), canonicalProof.end()))
        return VerifyResult::MalformedProof;

    try {
        return address.verify_own(MessageScalar(message), proof) ? VerifyResult::Ok
                                                                 : VerifyResult::Mismatch;
    } catch (const std::exception&) {
        // A proof that deserializes but holds junk group elements throws out of libspark
        // rather than returning false. Either way the message is not proven.
        return VerifyResult::Mismatch;
    }
}

} // namespace spark
