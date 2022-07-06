#include "spend_transaction.h"

namespace spark {

SpendTransaction::SpendTransaction(
        const Params* params) {
    this->params = params;
}

SpendTransaction::SpendTransaction(
	const Params* params,
	const FullViewKey& full_view_key,
	const SpendKey& spend_key,
	const std::vector<Coin>& in_coins,
	const std::vector<std::vector<unsigned char>>& roots,
	const std::vector<InputCoinData>& inputs,
	const uint64_t f,
	const std::vector<OutputCoinData>& outputs
) {
	this->params = params;

	// Size parameters
	const std::size_t w = inputs.size(); // number of consumed coins
	const std::size_t t = outputs.size(); // number of generated coins
	const std::size_t N = in_coins.size(); // size of cover set

	// Ensure we have enough Merkle roots
	if (roots.size() != w) {
		throw std::invalid_argument("Bad number of roots for spend transaction");
	}
	this->roots = roots;

	// Prepare input-related vectors
	this->in_coins = in_coins; // input cover set
	this->S1.reserve(w); // serial commitment offsets
	this->C1.reserve(w); // value commitment offsets
	this->grootle_proofs.reserve(w); // Grootle one-of-many proofs
	this->T.reserve(w); // linking tags

	this->f = f; // fee

	// Prepare Chaum vectors
	std::vector<Scalar> chaum_x, chaum_y, chaum_z;

	// Prepare output vector
	this->out_coins.reserve(t); // coins
	std::vector<Scalar> k; // nonces

	// Parse out serial and value commitments from the cover set for use in proofs
	std::vector<GroupElement> S, C;
	S.resize(N);
	C.resize(N);
	for (std::size_t i = 0; i < N; i++) {
		S[i] = in_coins[i].S;
		C[i] = in_coins[i].C;
	}

	// Prepare inputs
	Grootle grootle(
		this->params->get_H(),
		this->params->get_G_grootle(),
		this->params->get_H_grootle(),
		this->params->get_n_grootle(),
		this->params->get_m_grootle()
	);
	for (std::size_t u = 0; u < w; u++) {
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
			this->roots[u],
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
	balance_statement += this->params->get_G()*Scalar(f);
	schnorr.prove(
		balance_witness,
		balance_statement,
		this->balance_proof
	);

	// Compute the binding hash
	Scalar mu = hash_bind(
		this->roots,
		this->out_coins,
		this->f,
		this->S1,
		this->C1,
		this->T,
		this->grootle_proofs,
		this->balance_proof,
		this->range_proof
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

std::vector<GroupElement>& SpendTransaction::getUsedLTags() {
    return T;
}


bool SpendTransaction::verify() {
	// Size parameters
	const std::size_t w = this->grootle_proofs.size();
	const std::size_t t = this->out_coins.size();
	const std::size_t N = this->in_coins.size();

	// Semantics
	if (this->S1.size() != w || this->C1.size() != w || this->T.size() != w || this->roots.size() != w) {
		throw std::invalid_argument("Bad spend transaction semantics");
	}
	if (N > (std::size_t)pow(this->params->get_n_grootle(), this->params->get_m_grootle())) {
		throw std::invalid_argument("Bad spend transaction semantics");
	}

	// Parse out serial and value commitments from the cover set for use in proofs
	std::vector<GroupElement> S, C;
	S.resize(N);
	C.resize(N);
	for (std::size_t i = 0; i < N; i++) {
		S[i] = this->in_coins[i].S;
		C[i] = this->in_coins[i].C;
	}

	// Parse out value commitments from the output set for use in proofs
	std::vector<GroupElement> C_out;
	C_out.resize(t);
	for (std::size_t j = 0; j < t; j++) {
		C_out[j] = this->out_coins[j].C;
	}

	// Consumed coins
	Grootle grootle(
		this->params->get_H(),
		this->params->get_G_grootle(),
		this->params->get_H_grootle(),
		this->params->get_n_grootle(),
		this->params->get_m_grootle()
	);

	// Verify all Grootle proofs in a batch
	std::vector<std::size_t> sizes;
	for (std::size_t u = 0; u < w; u++) {
		sizes.emplace_back(N);
	}
	if (!grootle.verify(S, this->S1, C, this->C1, this->roots, sizes, this->grootle_proofs)) {
		return false;
	}
	
	// Compute the binding hash
	Scalar mu = hash_bind(
		this->roots,
		this->out_coins,
		this->f,
		this->S1,
		this->C1,
		this->T,
		this->grootle_proofs,
		this->balance_proof,
		this->range_proof
	);

	// Verify the authorizing Chaum proof
	Chaum chaum(
		this->params->get_F(),
		this->params->get_G(),
		this->params->get_H(),
		this->params->get_U()
	);
	if (!chaum.verify(mu, this->S1, this->T, this->chaum_proof)) {
		return false;
	}

	// Verify the aggregated range proof
	BPPlus range(
		this->params->get_G(),
		this->params->get_H(),
		this->params->get_G_range(),
		this->params->get_H_range(),
		64
	);
	if (!range.verify(C_out, this->range_proof)) {
		return false;
	}

	// Verify the balance proof
	Schnorr schnorr(this->params->get_H());
	GroupElement balance_statement;
	for (std::size_t u = 0; u < w; u++) {
		balance_statement += this->C1[u];
	}
	for (std::size_t j = 0; j < t; j++) {
		balance_statement += this->out_coins[j].C.inverse();
	}
	balance_statement += this->params->get_G()*Scalar(this->f);
	if(!schnorr.verify(
		balance_statement,
		this->balance_proof
	)) {
		return false;
	}

	return true;
}

// Hash-to-scalar function H_bind
Scalar SpendTransaction::hash_bind(
	const std::vector<std::vector<unsigned char>>& roots,
    const std::vector<Coin>& out_coins,
    const uint64_t f,
    const std::vector<GroupElement>& S1,
    const std::vector<GroupElement>& C1,
    const std::vector<GroupElement>& T,
    const std::vector<GrootleProof>& grootle_proofs,
    const SchnorrProof& balance_proof,
	const BPPlusProof& range_proof
) {
    Hash hash(LABEL_HASH_BIND);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);

	// Perform the serialization and hashing
	stream << roots,
    stream << out_coins;
    stream << f;
    stream << S1;
    stream << C1;
    stream << T;
    stream << grootle_proofs;
    stream << balance_proof;
	stream << range_proof;
    hash.include(stream);

    return hash.finalize_scalar();
}

}
