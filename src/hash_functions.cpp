#include "hash_functions.h"
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
    vector<unsigned char> bnData(coin.value.memoryRequired());
    coin.value.serialize(&bnData[0]);

    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(&bnData[0], bnData.size()).Finalize(hash);

    // take the first bytes of "hash".
    std::size_t result;
    std::memcpy(&result, hash, sizeof(std::size_t));
    return result;
}

} // namespace sigma
