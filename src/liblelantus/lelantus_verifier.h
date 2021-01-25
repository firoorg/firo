#ifndef FIRO_LIBLELANTUS_LELANTUSVERIFIER_H
#define FIRO_LIBLELANTUS_LELANTUSVERIFIER_H

#include "schnorr_verifier.h"
#include "sigmaextended_verifier.h"
#include "range_verifier.h"
#include "lelantus_primitives.h"
#include "coin.h"
namespace lelantus {
class LelantusVerifier {
public:
    LelantusVerifier(const Params* p);

    bool verify(
            const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets, //pass anonymity sets as a map, key is the id of the set, value is the set, we need this for multiple anonymity set support
            const std::vector<Scalar>& serialNumbers,  // we pass serials as a vector, where the element has it's pair at groupIds vector, first is the serial, second is anonymity set id for it
            const std::vector<uint32_t>& groupIds,
            const Scalar& Vin,
            uint64_t Vout,
            uint64_t fee,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof);

    bool verify(
            const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,  //pass anonymity sets as a map, key is the id of the set, value is the set, we need this for multiple anonymity set support
            const std::vector<Scalar>& serialNumbers,  // we pass serials as a vector, where the element has it's pair at groupIds vector, first is the serial, second is anonymity set id for it
            const std::vector<uint32_t>& groupIds,
            const Scalar& Vin,
            uint64_t Vout,
            uint64_t fee,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof,
            Scalar& x,
            bool fSkipVerification = false);

private:
    bool verify_sigma(
            const std::vector<std::vector<PublicCoin>>& anonymity_sets,
            const std::vector<std::vector<Scalar>>& Sin,
            const std::vector<PublicCoin>& Cout,
            const std::vector<SigmaExtendedProof> &sigma_proofs,
            Scalar& x,
            Scalar& zV,
            Scalar& zR,
            bool fSkipVerification = false);
    bool verify_rangeproof(
            const std::vector<PublicCoin>& Cout,
            const RangeProof& bulletproofs);
    bool verify_schnorrproof(
            const Scalar& x,
            const Scalar& zV,
            const Scalar& zR,
            const Scalar& Vin,
            const Scalar& Vout,
            const Scalar fee,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof);

private:
    const Params* params;

};
}// namespace lelantus

#endif //FIRO_LIBLELANTUS_LELANTUSVERIFIER_H
