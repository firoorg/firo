#include "spend_metadata.h"

namespace sigma {

SpendMetaData::SpendMetaData(
        const arith_uint256& accumulatorId,
        const uint256& blockHash,
        const uint256& txHash)
    : accumulatorId(accumulatorId)
    , blockHash(blockHash)
    , txHash(txHash)
{

}

} // namespace sigma
