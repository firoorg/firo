#include "primitives.h"
#include "../hash.h"


uint256 CSparkMintMeta::GetNonceHash() const {
    if(!nonceHash)
        nonceHash.reset(primitives::GetNonceHash(k));
    return *nonceHash;
}

namespace primitives {

uint256 GetNonceHash(const secp_primitives::Scalar& nonce) {
    CDataStream ss(SER_GETHASH, 0);
    ss << "nonce_hash";
    ss << nonce;
    return Hash(ss.begin(), ss.end());
}

} // namespace primitives