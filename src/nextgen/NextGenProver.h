#ifndef ZCOIN_NEXTGENPROVER_H
#define ZCOIN_NEXTGENPROVER_H

#include "SchnorrProver.h"
#include "SigmaPlusProver.h"
#include "NextGenPrimitives.h"
#include "Coin.h"

namespace nextgen {

class NextGenProver {
public:
    NextGenProver(const Params* p);
    void proof(
            const std::vector <PublicCoin>& c,
            const Scalar& Vin,
            const std::vector <PrivateCoin>& Cin,
            const std::vector <uint64_t>& indexes,
            const Scalar& Vout,
            const std::vector <PrivateCoin>& Cout,
            const Scalar& f,
            NextGenProof& proof_out);

    void generate_sigma_proofs(
            const std::vector<PublicCoin>& c,
            const std::vector<PrivateCoin>& Cin,
            const std::vector<uint64_t>& indexes,
            Scalar& x,
            std::vector<SigmaPlusProof<Scalar, GroupElement>>& sigma_proofs);

private:
    const Params* params;
};
}// namespace nextgen

#endif //ZCOIN_NEXTGENPROVER_H
