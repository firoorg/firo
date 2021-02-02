#include "spend_metadata.h"

namespace lelantus {

SpendMetaData::SpendMetaData(
        const std::map<uint32_t, uint256>& groupBlockHashes,
        const uint256& txHash)
        : txHash(txHash) {
    coinGroupIdAndBlockHash.reserve(groupBlockHashes.size());

    for(const auto& idAndHash : groupBlockHashes) {
        coinGroupIdAndBlockHash.emplace_back(idAndHash.first, idAndHash.second);
    }
}

} // namespace lelantus