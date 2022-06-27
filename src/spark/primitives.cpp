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

uint256 GetLTagHash(const secp_primitives::GroupElement& tag) {
    CDataStream ss(SER_GETHASH, 0);
    ss << "tag_hash";
    ss << tag;
    return Hash(ss.begin(), ss.end());
}

uint256 GetSparkCoinHash(const spark::Coin& coin) {
    return coin.getHash();
}

} // namespace primitives

namespace spark {

std::size_t CoinHash::operator ()(const spark::Coin& coin) const noexcept {
    uint256 hash = primitives::GetSparkCoinHash(coin);

    std::size_t result;
    std::memcpy(&result, hash.begin(), sizeof(std::size_t));
    return result;
}

std::size_t CLTagHash::operator ()(const secp_primitives::GroupElement& tag) const noexcept {
    uint256 hash = primitives::GetLTagHash(tag);

    std::size_t result;
    std::memcpy(&result, hash.begin(), sizeof(std::size_t));
    return result;
}


CMintedCoinInfo CMintedCoinInfo::make(int coinGroupId, int nHeight) {
    CMintedCoinInfo coinInfo;
    coinInfo.coinGroupId = coinGroupId;
    coinInfo.nHeight = nHeight;
    return coinInfo;
}

} // namespace spark