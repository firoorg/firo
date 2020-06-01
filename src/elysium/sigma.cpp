#include "sigma.h"

#include "sigmadb.h"
#include "sigmaprimitives.h"

#include "../main.h"
#include "../sync.h"

#include <iterator>
#include <vector>

namespace elysium {

bool VerifySigmaSpend(
    PropertyId property,
    SigmaDenomination denomination,
    SigmaMintGroup group,
    size_t groupSize,
    const SigmaProof& proof,
    const secp_primitives::Scalar& serial,
    bool fPadding)
{
    std::vector<SigmaPublicKey> anonimitySet; // Don't preallocate the vector due to it will allow attacker to crash all client.

    {
        LOCK(cs_main);
        sigmaDb->GetAnonimityGroup(property, denomination, group, groupSize, std::back_inserter(anonimitySet));
    }

    // If the size of anonimity set is not the expected once then no need to verify the proof.
    if (anonimitySet.size() != groupSize) {
        return false;
    }

    return proof.Verify(serial, anonimitySet.begin(), anonimitySet.end(), fPadding);
}

} // namespace elysium
