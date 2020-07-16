#include "spend_metadata.h"

namespace lelantus {

SpendMetaData::SpendMetaData(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymitySets,
        const std::vector<uint256>& groupBlockHashes,
        const uint256& txHash)
        : txHash(txHash) {
    if(groupBlockHashes.size() != anonymitySets.size())
        throw std::invalid_argument("Mismatch blockHashes and anonymity sets sizes.");

    coinGroupIdAndBlockHash.reserve(groupBlockHashes.size());

    int i = 0;
    for(const auto& set : anonymitySets) {
        coinGroupIdAndBlockHash.emplace_back(set.first, groupBlockHashes[i]);
        i++;
    }
}

} // namespace lelantus