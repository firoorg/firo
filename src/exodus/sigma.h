#ifndef ZCOIN_EXODUS_SIGMA_H
#define ZCOIN_EXODUS_SIGMA_H

#include "property.h"
#include "sigmaprimitives.h"

#include <stddef.h>

namespace exodus {

bool VerifySigmaSpend(
    PropertyId property,
    SigmaDenomination denomination,
    SigmaMintGroup group,
    size_t groupSize,
    const SigmaProof& proof,
    bool fPadding);

} // namespace exodus

#endif // ZCOIN_EXODUS_SIGMA_H
