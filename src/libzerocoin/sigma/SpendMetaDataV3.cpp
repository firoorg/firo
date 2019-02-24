#include "SpendMetaDataV3.h"

namespace sigma {

SpendMetaDataV3::SpendMetaDataV3(arith_uint256 accumulatorId, uint256 blockHash, uint256 txHash)
    : accumulatorId(accumulatorId)
    , blockHash(blockHash)
    , txHash(txHash)
{

}

} /* namespace libzerocoin */
