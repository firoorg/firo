#include "spend_metadata.h"

namespace lelantus {


SpendMetaData::SpendMetaData(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<uint256>& groupBlockHashes,
        const uint256& txHash) {
    if(groupBlockHashes.size() != anonymity_sets.size())
        throw ZerocoinException("Mismatch blockHashes and anonymity sets sizes.");

    coinGroupIdAndBlockHash.reserve(groupBlockHashes.size());

    int i = 0;
    for(const auto& set : anonymity_sets) {
        coinGroupIdAndBlockHash.emplace_back(std::make_pair(set.first, groupBlockHashes[i]));
    }
}

} // namespace lelantus