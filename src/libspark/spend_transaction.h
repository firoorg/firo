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

// Note that cover sets are treated as monotonic, meaning they grow over time (up to some implementation-defined limit)
// To support efficient batching, we track which set each spend references
// If spends share a `cover_set_id`, we assume the corresponding `cover_set` vectors have a subset relationship
// This relationship _must_ be checked elsewhere, as we simply use the largest `cover_set` for each `cover_set_id`!
struct InputCoinData {
	uint64_t cover_set_id; // an identifier for the monotonically-growing set of which `cover_set` is a subset
	std::vector<Coin> cover_set; // set of coins used as a cover set for the spend
	std::vector<unsigned char> cover_set_representation; // a unique representation for the ordered elements of the partial `cover_set` used in the spend
	std::size_t cover_set_size; // the size of the partial cover set used by the spend; should be canonical with `cover_set_representation`
	std::size_t index; // index of the coin in the cover set
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
            const Params* params);

	SpendTransaction(
		const Params* params,
		const FullViewKey& full_view_key,
		const SpendKey& spend_key,
		const std::vector<InputCoinData>& inputs,
		const uint64_t f,
		const std::vector<OutputCoinData>& outputs
	);

	uint64_t getFee();
    std::vector<GroupElement>& getUsedLTags();

	static bool verify(const Params* params, const std::vector<SpendTransaction>& transactions);
	static bool verify(const SpendTransaction& transaction);

	static Scalar hash_bind(
        const std::vector<Coin>& out_coins,
        const uint64_t f,
		const std::vector<std::vector<unsigned char>>& cover_set_representations,
        const std::vector<GroupElement>& S1,
        const std::vector<GroupElement>& C1,
        const std::vector<GroupElement>& T,
        const std::vector<GrootleProof>& grootle_proofs,
        const SchnorrProof& balance_proof,
		const BPPlusProof& range_proof
    );

private:
	const Params* params;
	std::vector<uint64_t> cover_set_ids;
	std::vector<std::vector<Coin>> cover_sets;
	std::vector<std::vector<unsigned char>> cover_set_representations;
	std::vector<std::size_t> cover_set_sizes;
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
