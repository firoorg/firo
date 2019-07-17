#include "coin_containers.h"
#include "crypto/sha256.h"

#include <vector>

namespace sigma {

std::size_t CScalarHash::operator ()(const Scalar& bn) const noexcept {
    vector<unsigned char> bnData(bn.memoryRequired());
    bn.serialize(&bnData[0]);

    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(&bnData[0], bnData.size()).Finalize(hash);

    // take the first bytes of "hash".
    std::size_t result;
    std::memcpy(&result, hash, sizeof(std::size_t));
    return result;
}

std::size_t CPublicCoinHash::operator ()(const sigma::PublicCoin& coin) const noexcept {
    vector<unsigned char> bnData(coin.getValue().memoryRequired());
    coin.getValue().serialize(&bnData[0]);

    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(&bnData[0], bnData.size()).Finalize(hash);

    // take the first bytes of "hash".
    std::size_t result;
    std::memcpy(&result, hash, sizeof(std::size_t));
    return result;
}


CMintedCoinInfo CMintedCoinInfo::make(CoinDenomination denomination,  int coinGroupId, int nHeight) {
    CMintedCoinInfo coinInfo;
    coinInfo.denomination = denomination;
    coinInfo.coinGroupId = coinGroupId;
    coinInfo.nHeight = nHeight;
    return coinInfo;
}

CSpendCoinInfo CSpendCoinInfo::make(CoinDenomination denomination,  int coinGroupId) {
    CSpendCoinInfo coinInfo;
    coinInfo.denomination = denomination;
    coinInfo.coinGroupId = coinGroupId;
    return coinInfo;
}


} // namespace sigma
