#include "spend_transaction.h"

namespace spark {

// Generate a spend transaction that consumes existing coins and generates new ones
SpendTransaction::SpendTransaction(
        const Params* params) {
    this->params = params;
}

SpendTransaction::SpendTransaction(
	const Params* params,
	const FullViewKey& full_view_key,
	const SpendKey& spend_key,
	const std::vector<InputCoinData>& inputs,
    const std::unordered_map<uint64_t, CoverSetData>& cover_set_data,
	const uint64_t f,
    const uint64_t vout,
	const std::vector<OutputCoinData>& outputs
) {
	this->params = params;

	// Size parameters
	const std::size_t w = inputs.size(); // number of consumed coins
	const std::size_t t = outputs.size(); // number of generated coins
	const std::size_t N = (std::size_t) std::pow(params->get_n_grootle(), params->get_m_grootle()); // size of cover sets

	// Prepare input-related vectors
	this->cover_set_ids.reserve(w); // cover set data and metadata
    this->setCoverSets(cover_set_data);
	this->S1.reserve(w); // serial commitment offsets
	this->C1.reserve(w); // value commitment offsets
	this->grootle_proofs.reserve(w); // Grootle one-of-many proofs
	this->T.reserve(w); // linking tags

	this->f = f; // fee
    this->vout = vout; // transparent output value

	// Prepare Chaum vectors
	std::vector<Scalar> chaum_x, chaum_y, chaum_z;

	// Prepare output vector
	this->out_coins.reserve(t); // coins
	std::vector<Scalar> k; // nonces

	// Prepare inputs
	Grootle grootle(
		this->params->get_H(),
		this->params->get_G_grootle(),
		this->params->get_H_grootle(),
		this->params->get_n_grootle(),
		this->params->get_m_grootle()
	);
	for (std::size_t u = 0; u < w; u++) {
		// Parse out cover set data for this spend
        uint64_t set_id = inputs[u].cover_set_id;
		this->cover_set_ids.emplace_back(set_id);
        if (cover_set_data.count(set_id) == 0)
            throw std::invalid_argument("Required set is not passed");

        const auto& cover_set = cover_set_data.at(set_id).cover_set;
        std::size_t set_size = cover_set.size();
        if (set_size > N)
            throw std::invalid_argument("Wrong set size");

        std::vector<GroupElement> S, C;
		S.reserve(set_size);
		C.reserve(set_size);
		for (std::size_t i = 0; i < set_size; i++) {
			S.emplace_back(cover_set[i].S);
			C.emplace_back(cover_set[i].C);
		}

		// Serial commitment offset
		this->S1.emplace_back(
			this->params->get_F()*inputs[u].s
			+ this->params->get_H().inverse()*SparkUtils::hash_ser1(inputs[u].s, full_view_key.get_D())
			+ full_view_key.get_D()
		);

		// Value commitment offset
		this->C1.emplace_back(
			this->params->get_G()*Scalar(inputs[u].v)
			+ this->params->get_H()*SparkUtils::hash_val1(inputs[u].s, full_view_key.get_D())
		);

		// Tags
		this->T.emplace_back(inputs[u].T);

		// Grootle proof
		this->grootle_proofs.emplace_back();
		std::size_t l = inputs[u].index;
		grootle.prove(
			l,
			SparkUtils::hash_ser1(inputs[u].s, full_view_key.get_D()),
			S,
			this->S1.back(),
			SparkUtils::hash_val(inputs[u].k) - SparkUtils::hash_val1(inputs[u].s, full_view_key.get_D()),
			C,
			this->C1.back(),
			this->cover_set_representations[set_id],
			this->grootle_proofs.back()
		);

		// Chaum data
		chaum_x.emplace_back(inputs[u].s);
		chaum_y.emplace_back(spend_key.get_r());
		chaum_z.emplace_back(SparkUtils::hash_ser1(inputs[u].s, full_view_key.get_D()).negate());
	}

	// Generate output coins and prepare range proof vectors
	std::vector<Scalar> range_v;
	std::vector<Scalar> range_r;
	std::vector<GroupElement> range_C;

	// Serial context for all outputs is the set of linking tags for this transaction, which must always be in a fixed order
    CDataStream serial_context(SER_NETWORK, PROTOCOL_VERSION);
	serial_context << this->T;

	for (std::size_t j = 0; j < t; j++) {
		// Nonce
		k.emplace_back();
		k.back().randomize();

		// Output coin
		this->out_coins.emplace_back();
		this->out_coins.back() = Coin(
			this->params,
			COIN_TYPE_SPEND,
			k.back(),
			outputs[j].address,
			outputs[j].v,
			outputs[j].memo,
			std::vector<unsigned char>(serial_context.begin(), serial_context.end())
		);

		// Range data
		range_v.emplace_back(outputs[j].v);
		range_r.emplace_back(SparkUtils::hash_val(k.back()));
		range_C.emplace_back(this->out_coins.back().C);
	}

	// Generate range proof
	BPPlus range(
		this->params->get_G(),
		this->params->get_H(),
		this->params->get_G_range(),
		this->params->get_H_range(),
		64
	);
	range.prove(
		range_v,
		range_r,
		range_C,
		this->range_proof
	);

	// Generate the balance proof
	Schnorr schnorr(this->params->get_H());
	GroupElement balance_statement;
	Scalar balance_witness;
	for (std::size_t u = 0; u < w; u++) {
		balance_statement += this->C1[u];
		balance_witness += SparkUtils::hash_val1(inputs[u].s, full_view_key.get_D());
	}
	for (std::size_t j = 0; j < t; j++) {
		balance_statement += this->out_coins[j].C.inverse();
		balance_witness -= SparkUtils::hash_val(k[j]);
	}
	balance_statement += (this->params->get_G()*Scalar(f + vout)).inverse();
	schnorr.prove(
		balance_witness,
		balance_statement,
		this->balance_proof
	);

	// Compute the binding hash
	Scalar mu = hash_bind(
		hash_bind_inner(
			this->cover_set_representations,
			this->C1,
			this->grootle_proofs,
			this->balance_proof,
			this->range_proof
		),
		this->out_coins,
		this->f + vout
	);

	// Compute the authorizing Chaum proof
	Chaum chaum(
		this->params->get_F(),
		this->params->get_G(),
		this->params->get_H(),
		this->params->get_U()
	);
	chaum.prove(
		mu,
		chaum_x,
		chaum_y,
		chaum_z,
		this->S1,
		this->T,
		this->chaum_proof
	);
}

uint64_t SpendTransaction::getFee() {
    return f;
}

const std::vector<GroupElement>& SpendTransaction::getUsedLTags() const {
    return T;
}

const std::vector<uint64_t>& SpendTransaction::getCoinGroupIds() {
    return cover_set_ids;
}

const std::vector<Coin>& SpendTransaction::getOutCoins() {
    return out_coins;
}

// Convenience wrapper for verifying a single spend transaction
bool SpendTransaction::verify(
        const SpendTransaction& transaction,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets) {
	std::vector<SpendTransaction> transactions = { transaction };
	return verify(transaction.params, transactions, cover_sets);
}

// Determine if a set of spend transactions is collectively valid
// NOTE: This assumes that the relationship between a `cover_set_id` and the provided `cover_set` is already valid and canonical!
// NOTE: This assumes that validity criteria relating to chain context have been externally checked!
bool SpendTransaction::verify(
        const Params* params,
        const std::vector<SpendTransaction>& transactions,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets) {
	// The idea here is to perform batching as broadly as possible
	// - Grootle proofs can be batched if they share a (partial) cover set
	// - Range proofs can always be batched arbitrarily
	// - Other parts of the transaction can be checked separately
	// - We try to verify in order of likely computational complexity, to fail early

	// Track range proofs to batch
	std::vector<std::vector<GroupElement>> range_proofs_C; // commitments for all range proofs
	std::vector<BPPlusProof> range_proofs; // all range proofs

	// Track cover sets across Grootle proofs to batch
	std::unordered_map<uint64_t, std::vector<std::pair<std::size_t, std::size_t>>> grootle_buckets;

	// Process each transaction
	for (std::size_t i = 0; i < transactions.size(); i++) {
		SpendTransaction tx = transactions[i];

		// Assert common parameters
		if (params != tx.params) {
			return false;
		}

		// Size parameters for this transaction
		const std::size_t w = tx.cover_set_ids.size(); // number of consumed coins
		const std::size_t t = tx.out_coins.size(); // number of generated coins
		const std::size_t N = (std::size_t) std::pow(params->get_n_grootle(), params->get_m_grootle()); // size of cover sets

		// Consumed coin semantics
		if (tx.S1.size() != w ||
			tx.C1.size() != w ||
			tx.T.size() != w ||
			tx.grootle_proofs.size() != w,
			tx.cover_set_sizes.size() != tx.cover_set_representations.size()) {
			throw std::invalid_argument("Bad spend transaction semantics");
		}

		// Cover set semantics
		for (const auto& set : cover_sets) {
			if (set.second.size() > N) {
				throw std::invalid_argument("Bad spend transaction semantics");
			}
		}

		// Store range proof with commitments
		range_proofs_C.emplace_back();
		for (std::size_t j = 0; j < t; j++) {
			range_proofs_C.back().emplace_back(tx.out_coins[j].C);
		}
		range_proofs.emplace_back(tx.range_proof);

		// Sort all Grootle proofs into buckets for batching based on common input sets
		for (std::size_t u = 0; u < w; u++) {
			grootle_buckets[tx.cover_set_ids[u]].emplace_back(std::pair<std::size_t, std::size_t>(i, u));
		}

		// Compute the binding hash
		Scalar mu = hash_bind(
			tx.hash_bind_inner(
				tx.cover_set_representations,
				tx.C1,
				tx.grootle_proofs,
				tx.balance_proof,
				tx.range_proof
			),
			tx.out_coins,
			tx.f + tx.vout
		);

		// Verify the authorizing Chaum-Pedersen proof
		Chaum chaum(
			tx.params->get_F(),
			tx.params->get_G(),
			tx.params->get_H(),
			tx.params->get_U()
		);
		if (!chaum.verify(mu, tx.S1, tx.T, tx.chaum_proof)) {
			return false;
		}

		// Verify the balance proof
		Schnorr schnorr(tx.params->get_H());
		GroupElement balance_statement;
		for (std::size_t u = 0; u < w; u++) {
			balance_statement += tx.C1[u];
		}
		for (std::size_t j = 0; j < t; j++) {
			balance_statement += tx.out_coins[j].C.inverse();
		}
        balance_statement += (tx.params->get_G()*Scalar(tx.f + tx.vout)).inverse();
        
		if(!schnorr.verify(
			balance_statement,
			tx.balance_proof
		)) {
			return false;
		}
	}

	// Verify all range proofs in a batch
	BPPlus range(
		params->get_G(),
		params->get_H(),
		params->get_G_range(),
		params->get_H_range(),
		64
	);
	if (!range.verify(range_proofs_C, range_proofs)) {
		return false;
	}

	// Verify all Grootle proofs in batches (based on cover set)
	// TODO: Finish this
	Grootle grootle(
		params->get_H(),
		params->get_G_grootle(),
		params->get_H_grootle(),
		params->get_n_grootle(),
		params->get_m_grootle()
	);
	for (auto grootle_bucket : grootle_buckets) {
		std::size_t cover_set_id = grootle_bucket.first;
		std::vector<std::pair<std::size_t, std::size_t>> proof_indexes = grootle_bucket.second;

		// Build the proof statement and metadata vectors from these proofs
		std::vector<GroupElement> S, S1, V, V1;
		std::vector<std::vector<unsigned char>> cover_set_representations;
		std::vector<std::size_t> sizes;
		std::vector<GrootleProof> proofs;

        std::size_t full_cover_set_size = cover_sets.at(cover_set_id).size();
        for (std::size_t i = 0; i < full_cover_set_size; i++) {
            S.emplace_back(cover_sets.at(cover_set_id)[i].S);
            V.emplace_back(cover_sets.at(cover_set_id)[i].C);
        }

		for (auto proof_index : proof_indexes) {
            const auto& tx = transactions[proof_index.first];
            if (!cover_sets.count(cover_set_id))
                throw std::invalid_argument("Cover set missing");
			// Because we assume all proofs in this list share a monotonic cover set, the largest such set is the one to use for verification
            if (!tx.cover_set_sizes.count(cover_set_id))
                throw std::invalid_argument("Cover set size missing");

			std::size_t this_cover_set_size = tx.cover_set_sizes.at(cover_set_id);

			// We always use the other elements
			S1.emplace_back(tx.S1[proof_index.second]);
			V1.emplace_back(tx.C1[proof_index.second]);
            if (!tx.cover_set_representations.count(cover_set_id))
                throw std::invalid_argument("Cover set representation missing");

			cover_set_representations.emplace_back(tx.cover_set_representations.at(cover_set_id));
			sizes.emplace_back(this_cover_set_size);
			proofs.emplace_back(tx.grootle_proofs[proof_index.second]);
		}

		// Verify the batch
		if (!grootle.verify(S, S1, V, V1, cover_set_representations, sizes, proofs)) {
            return false;
        }
	}

	// Any failures have been identified already, so the batch is valid
	return true;
}

// Hash function H_bind_inner
// This function pre-hashes auxiliary data that makes things easier for a limited signer who cannot process the data directly
// Its value is then used as part of the binding hash, which a limited signer can verify as part of the signing process
std::vector<unsigned char> SpendTransaction::hash_bind_inner(
	const std::unordered_map<uint64_t, std::vector<unsigned char>>& cover_set_representations,
	const std::vector<GroupElement>& C1,
	const std::vector<GrootleProof>& grootle_proofs,
	const SchnorrProof& balance_proof,
	const BPPlusProof& range_proof
) {
    Hash hash(LABEL_HASH_BIND_INNER);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
	stream << cover_set_representations;
    stream << S1;
    stream << C1;
    stream << T;
    stream << grootle_proofs;
    stream << balance_proof;
	stream << range_proof;
    hash.include(stream);

	return hash.finalize();
}

// Hash-to-scalar function H_bind
// This function must accept pre-hashed data from `H_bind_inner` intended to correspond to the signing operation
Scalar SpendTransaction::hash_bind(
	const std::vector<unsigned char> hash_bind_inner,
    const std::vector<Coin>& out_coins,
    const uint64_t f_
) {
	Hash hash(LABEL_HASH_BIND);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
	stream << hash_bind_inner,
	stream << out_coins;
	stream << f_;
	hash.include(stream);

    return hash.finalize_scalar();
}

void SpendTransaction::setBlockHashes(const std::map<uint64_t, uint256>& idAndHashes) {
    set_id_blockHash = idAndHashes;
}

const std::map<uint64_t, uint256>& SpendTransaction::getBlockHashes() {
    return set_id_blockHash;
}

}
