#include "mint_transaction.h"

namespace spark {

MintTransaction::MintTransaction(
	const Params* params,
	const std::vector<MintedCoinData>& outputs
) {
	// Important note: This construction assumes that the public coin values are correct according to higher-level consensus rules!

	this->params = params;
	Schnorr schnorr(this->params->get_H());

	for (std::size_t j = 0; j < outputs.size(); j++) {
		MintedCoinData output = outputs[j];

		// Generate the coin
		Scalar k;
		k.randomize();
		this->coins.emplace_back(Coin(
			this->params,
			COIN_TYPE_MINT,
			k,
			output.address,
			output.v,
			output.memo
		));

		// Generate the value proof
		this->value_proofs.emplace_back();
		schnorr.prove(
			SparkUtils::hash_val(k),
			this->coins[j].C + this->params->get_G().inverse()*Scalar(this->coins[j].v),
			this->value_proofs.back()
		);
	}

}

bool MintTransaction::verify() {
	// Size check
	if (this->coins.size() != this->value_proofs.size()) {
		throw std::invalid_argument("Bad mint transaction semantics");
	}

	// Verify the value proofs
	Schnorr schnorr(this->params->get_H());

	for (std::size_t j = 0; j < this->coins.size(); j++) {
		if (!schnorr.verify(
			this->coins[j].C + this->params->get_G().inverse()*Scalar(this->coins[j].v),
			this->value_proofs[j]
		)) {
			return false;
		}
	}

	return true;
}

}
