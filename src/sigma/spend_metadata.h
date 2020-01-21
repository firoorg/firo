#ifndef SPENDMETADATA_V3_H_
#define SPENDMETADATA_V3_H_

#include "../arith_uint256.h"
#include "../uint256.h"
#include "../serialize.h"

namespace sigma {

/** Any meta data needed for actual bitcoin integration.
 * Can extended provided the getHash() function is updated
 */
class SpendMetaData {
public:
	/**
	 * Creates meta data associated with a coin spend
	 * @param accumulatorId Number of the coingroup, in which this spend happens.
	 * @param blockHash hash of the block against which the spend is made.
	 * @param txHash hash of transaction.
	 */
    SpendMetaData(
        const arith_uint256& accumulatorId,
        const uint256& blockHash,
        const uint256& txHash);


    // Coin group ID to which the coin being spent belongs to.
    arith_uint256 accumulatorId; 

    /**
     * The hash of the block containing the accumulator CoinSpend
	 * proves membership in.
     */
    uint256 blockHash;

	/** Contains the hash of the rest of transaction
	 * spending a zerocoin (excluding the coinspend proof)
	 */
    uint256 txHash; // The Hash of the rest of the transaction the spend proof is n.

	// Allows us to sign the transaction.
	ADD_SERIALIZE_METHODS;
	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action) {
		READWRITE(accumulatorId);
		READWRITE(blockHash);
		READWRITE(txHash);
	}
};

} // namespace libzerocoin

#endif // SPENDMETADATA_V3_H_
