#ifndef COIN_CONTAINERS_H
#define COIN_CONTAINERS_H

#include <secp256k1/include/Scalar.h>
#include "liblelantus/coin.h"

#include <unordered_map>

namespace lelantus {

// This struct is used to keep mint and jmint value data into block index for mobile recovery, it will use more space,
// Use this version of code in case you need mobile api
struct MintValueData {
    bool isJMint = false;
    uint64_t amount;
    std::vector<unsigned char> encryptedValue;
    uint256 txHash;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(isJMint);
        READWRITE(amount);
        READWRITE(encryptedValue);
        READWRITE(txHash);
    }
};

// Custom hash for Scalar values.
struct CScalarHash {
    std::size_t operator()(const secp_primitives::Scalar& bn) const noexcept;
};

// Custom hash for the public coin.
struct CPublicCoinHash {
    std::size_t operator()(const lelantus::PublicCoin& coin) const noexcept;
};

struct CMintedCoinInfo {
    int coinGroupId;
    int nHeight;

    static CMintedCoinInfo make(int coinGroupId, int nHeight);
};

using mint_info_container = std::unordered_map<lelantus::PublicCoin, CMintedCoinInfo, lelantus::CPublicCoinHash>;

} // namespace lelantus


#endif // COIN_CONTAINERS_H
