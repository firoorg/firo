#include "SpendMetaDataV3.h"

namespace sigma {

SpendMetaDataV3::SpendMetaDataV3(
        const arith_uint256& accumulatorId,
        const uint256& blockHash,
        const uint256& txHash)
    : accumulatorId(accumulatorId)
    , blockHash(blockHash)
    , txHash(txHash)
{

}

} /* namespace libzerocoin */
