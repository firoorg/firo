#ifndef ZCOIN_LIBLELANTUS_SPENDMETADATA_H_
#define ZCOIN_LIBLELANTUS_SPENDMETADATA_H_

#include "../uint256.h"
#include "../serialize.h"
#include "coin.h"

namespace lelantus {

class SpendMetaData {
public:

    SpendMetaData(
            const std::map<uint32_t, std::vector<PublicCoin>>& anonymitySets,
            const std::vector<uint256>& groupBlockHashes,
            const uint256& txHash);

    std::vector<std::pair<uint32_t, uint256>> coinGroupIdAndBlockHash;

    uint256 txHash; // The Hash of the rest of the transaction the spend proof is in.

	// Allows us to sign the transaction.
	ADD_SERIALIZE_METHODS;
	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action) {
		READWRITE(coinGroupIdAndBlockHash);
		READWRITE(txHash);
	}
};

} // namespace lelantus

#endif // ZCOIN_LIBLELANTUS_SPENDMETADATA_H_
