#ifndef ZCOIN_NEXTGENVERIFIER_H
#define ZCOIN_NEXTGENVERIFIER_H

#include "SchnorrVerifier.h"
#include "SigmaPlusVerifier.h"
#include "NextGenPrimitives.h"
#include "Coin.h"
namespace nextgen {
class NextGenVerifier {
public:
    NextGenVerifier(const Params* p);

    bool verify(
            const std::vector<PublicCoin>& c,
            const std::vector<Scalar>& Sin,
            const Scalar& Vin,
            const Scalar& Vout,
            const Scalar f,
            const std::vector<PublicCoin>& Cout,
            const NextGenProof& proof);

private:
    const Params* params;

};
}// namespace nextgen

#endif //ZCOIN_NEXTGENVERIFIER_H
