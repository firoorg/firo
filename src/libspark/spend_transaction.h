#ifndef FIRO_SPARK_SPEND_TRANSACTION_H
#define FIRO_SPARK_SPEND_TRANSACTION_H
#include "keys.h"
#include "coin.h"
#include "schnorr.h"
#include "util.h"
#include "grootle.h"
#include "bpplus.h"
#include "chaum.h"

namespace spark {

using namespace secp_primitives;

struct InputCoinData {
	std::size_t index; // index in cover set
	Scalar s; // serial number
	GroupElement T; // tag
	uint64_t v; // value
	Scalar k; // nonce
};

struct OutputCoinData {
	Address address;
	uint64_t v;
	std::string memo;
};

class SpendTransaction {
public:
	SpendTransaction(
		const Params* params,
		const FullViewKey& full_view_key,
		const SpendKey& spend_key,
		const std::vector<Coin>& in_coins,
		const std::vector<InputCoinData>& inputs,
		const uint64_t f,
		const std::vector<OutputCoinData>& outputs
	);
	bool verify();
    
	static Scalar hash_bind(
        const std::vector<Coin>& in_coins,
        const std::vector<Coin>& out_coins,
        const uint64_t f,
        const std::vector<GroupElement>& S1,
        const std::vector<GroupElement>& C1,
        const std::vector<GroupElement>& T,
        const std::vector<GrootleProof>& grootle_proofs,
        const SchnorrProof& balance_proof,
		const BPPlusProof& range_proof
    );

private:
	const Params* params;
	std::vector<Coin> in_coins;
	std::vector<Coin> out_coins;
	uint64_t f;
	std::vector<GroupElement> S1, C1, T;
	std::vector<GrootleProof> grootle_proofs;
	ChaumProof chaum_proof;
	SchnorrProof balance_proof;
	BPPlusProof range_proof;
};

}

#endif
