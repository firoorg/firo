#ifndef FIRO_SPATS_UTIL_H
#define FIRO_SPATS_UTIL_H
#include "../crypto/aes.h"
#include "../secp256k1/include/GroupElement.h"
#include "../secp256k1/include/Scalar.h"
#include "../streams.h"
#include "../util.h"
#include "../version.h"
#include "../libspark/hash.h"
#include "../libspark/kdf.h"
#include "../libspark/util.h"

namespace spats {

using namespace secp_primitives;

// Useful serialization constant
const std::size_t SCALAR_ENCODING = 32;

// Base protocol separator
const std::string LABEL_PROTOCOL= "SPATS";
const std::string LABEL_TRANSCRIPT_BPPLUS = "BULLETPROOF_PLUS_V2";
const std::string LABEL_TRANSCRIPT_BASE = "BASE_ASSET_V1";
const std::string LABEL_TRANSCRIPT_TYPE = "TYPEEQUALITY_V1";
const std::string LABEL_TRANSCRIPT_BALANCE = "BALANCE_V1";
} // namespace spats

#endif
