#ifndef FIRO_LIBLELANTUS_LELANTUSPROVER_H
#define FIRO_LIBLELANTUS_LELANTUSPROVER_H

#include "schnorr_prover.h"
#include "sigmaextended_prover.h"
#include "range_prover.h"
#include "coin.h"
#include "chain.h"
extern CChain chainActive;

namespace lelantus {

class LelantusProver {
public:
    LelantusProver(const Params* p, unsigned int v);
    void proof(
            const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
            const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
            const Scalar& Vin,
            const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
            const std::vector <size_t>& indexes,
            const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
            const Scalar& Vout,
            const std::vector <PrivateCoin>& Cout,
            const Scalar& fee,
            LelantusProof& proof_out);

private:
    void generate_sigma_proofs(
            const std::map<uint32_t, std::vector<PublicCoin>>& c,
            const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
            const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
            const std::vector<PrivateCoin>& Cout,
            const std::vector<size_t>& indexes,
            const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
            Scalar& x,
            unique_ptr<ChallengeGenerator>& challengeGenerator,
            std::vector<Scalar>& Yk_sum,
            std::vector<SigmaExtendedProof>& sigma_proofs);

    void generate_bulletproofs(
            const std::vector <PrivateCoin>& Cout,
            RangeProof& bulletproofs);

private:
    const Params* params;
    unsigned int version;
};
}// namespace lelantus

#endif //FIRO_LIBLELANTUS_LELANTUSPROVER_H
