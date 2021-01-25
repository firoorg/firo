#ifndef FIRO_LIBLELANTUS_LELANTUSPROVER_H
#define FIRO_LIBLELANTUS_LELANTUSPROVER_H

#include "schnorr_prover.h"
#include "sigmaextended_prover.h"
#include "range_prover.h"
#include "coin.h"

namespace lelantus {

class LelantusProver {
public:
    LelantusProver(const Params* p);
    void proof(
            const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets, //pass anonymity sets as a map, key is the id of the set, value is the set, we need this for multiple anonymity set support
            const Scalar& Vin,
            const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,  // we pass spending coins as a pair with anonymity set id, to which it belongs
            const std::vector <size_t>& indexes,
            const Scalar& Vout,
            const std::vector <PrivateCoin>& Cout,
            const Scalar& fee,
            LelantusProof& proof_out);

private:
    void generate_sigma_proofs(
            const std::map<uint32_t, std::vector<PublicCoin>>& c, //pass anonymity sets as a map, key is the id of the set, value is the set, we need this for multiple anonymity set support
            const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,  // we pass spending coins as a pair with anonymity set id, to which it belongs
            const std::vector<PrivateCoin>& Cout,
            const std::vector<size_t>& indexes,
            Scalar& x,
            std::vector<Scalar>& Yk_sum,
            std::vector<SigmaExtendedProof>& sigma_proofs);

    void generate_bulletproofs(
            const std::vector <PrivateCoin>& Cout,
            RangeProof& bulletproofs);

private:
    const Params* params;
};
}// namespace lelantus

#endif //FIRO_LIBLELANTUS_LELANTUSPROVER_H
