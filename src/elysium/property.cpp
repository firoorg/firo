#include "property.h"

#include "elysium.h"
#include "rules.h"
#include "utilsbitcoin.h"

#include "../chainparams.h"

namespace elysium {

bool IsEnabledFlag(SigmaStatus status)
{
    return status == SigmaStatus::SoftEnabled || status == SigmaStatus::HardEnabled;
}

bool IsRequireCreationFee(EcosystemId ecosystem)
{
    return IsRequireCreationFee(ecosystem, GetHeight());
}

bool IsRequireCreationFee(EcosystemId ecosystem, int block)
{
    return IsRequireCreationFee(ecosystem, block, Params().NetworkIDString());
}

bool IsRequireCreationFee(EcosystemId ecosystem, int block, const std::string& network)
{
    if (ecosystem != ELYSIUM_PROPERTY_ELYSIUM) {
        return false;
    }

    return block >= ConsensusParams(network).PROPERTY_CREATION_FEE_BLOCK;
}

} // namespace elysium
