#ifndef COIN_CONTAINERS_H
#define COIN_CONTAINERS_H

#include "sigma/Scalar.h"
#include "sigma/coin.h"

#include <unordered_map>

namespace sigma {

// Custom hash for Scalar values.
struct CScalarHash {
    std::size_t operator()(const secp_primitives::Scalar& bn) const noexcept;
};

// Custom hash for the public coin.
struct CPublicCoinHash {
    std::size_t operator()(const sigma::PublicCoin& coin) const noexcept;
};

struct CMintedCoinInfo {
    CoinDenomination denomination;
    int coinGroupId;
    int nHeight;

    static CMintedCoinInfo make(CoinDenomination denomination,  int coinGroupId, int nHeight);
};

struct CSpendCoinInfo {
    CoinDenomination denomination;
    int coinGroupId;

    static CSpendCoinInfo make(CoinDenomination denomination,  int coinGroupId);

    size_t GetSerializeSize(int nType, int nVersion) const {
        return 2 *sizeof(int64_t);
    }
    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const {
        int64_t tmp = int64_t(denomination);
        s << tmp;
        tmp = coinGroupId;
        s << tmp;
    }
    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion) {
        int64_t tmp;
        s >> tmp; denomination = CoinDenomination(tmp);
        s >> tmp; coinGroupId = int(tmp);
    }

};

using mint_info_container = std::unordered_map<sigma::PublicCoin, CMintedCoinInfo, sigma::CPublicCoinHash>;
using spend_info_container = std::unordered_map<Scalar, CSpendCoinInfo, sigma::CScalarHash>;

} // namespace sigma

#endif // COIN_CONTAINERS_H
