#ifndef ZCOIN_LELANTUSVERIFIER_H
#define ZCOIN_LELANTUSVERIFIER_H

#include "schnorr_verifier.h"
#include "sigmaplus_verifier.h"
#include "range_verifier.h"
#include "lelantus_primitives.h"
#include "coin.h"
namespace lelantus {
class LelantusVerifier {
public:
    LelantusVerifier(const Params* p);

    bool verify(
            const std::vector<PublicCoin>& c,
            const std::vector<Scalar>& Sin,
            const Scalar& Vin,
            const Scalar& Vout,
            const Scalar f,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof);

private:
    const Params* params;

};
}// namespace lelantus

#endif //ZCOIN_LELANTUSVERIFIER_H
