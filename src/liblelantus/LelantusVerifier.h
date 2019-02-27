#ifndef ZCOIN_LELANTUSVERIFIER_H
#define ZCOIN_LELANTUSVERIFIER_H

#include "SchnorrVerifier.h"
#include "SigmaPlusVerifier.h"
#include "RangeVerifier.h"
#include "LelantusPrimitives.h"
#include "Coin.h"
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
