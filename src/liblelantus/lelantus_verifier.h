#ifndef ZCOIN_LIBLELANTUS_LELANTUSVERIFIER_H
#define ZCOIN_LIBLELANTUS_LELANTUSVERIFIER_H

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
            const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
            const std::vector<Scalar>& serialNumbers,
            const std::vector<uint32_t>& groupIds,
            const Scalar& Vin,
            const Scalar& Vout,
            const Scalar f,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof);

private:
    bool verify_sigma(
            const std::vector<std::vector<PublicCoin>>& anonymity_sets,
            const std::vector<std::vector<Scalar>>& Sin,
            const std::vector<SigmaPlusProof<Scalar, GroupElement>> &sigma_proofs,
            Scalar& x,
            Scalar& zV,
            Scalar& zR);
    bool verify_rangeproof(
            const std::vector<PublicCoin>& Cout,
            const RangeProof<Scalar, GroupElement>& bulletproofs);
    bool verify_schnorrproof(
            const Scalar& x,
            const Scalar& zV,
            const Scalar& zR,
            const Scalar& Vin,
            const Scalar& Vout,
            const Scalar f,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof);

private:
    const Params* params;

};
}// namespace lelantus

#endif //ZCOIN_LIBLELANTUS_LELANTUSVERIFIER_H
