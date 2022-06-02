#include "mint_transaction.h"

namespace spark {

MintTransaction::MintTransaction(
	const Params* params,
	const std::vector<MintedCoinData>& outputs,
	const std::vector<unsigned char>& serial_context
) {
	// Important note: This construction assumes that the public coin values are correct according to higher-level consensus rules!
	// Important note: For pool transition transactions, the serial context should contain unique references to all base-layer spent assets, in order to ensure the resulting serial commitment is bound to this transaction

	this->params = params;
	Schnorr schnorr(this->params->get_H());

	std::vector<GroupElement> value_statement;
	std::vector<Scalar> value_witness;

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
			output.memo,
			serial_context
		));

		// Prepare the value proof
		value_statement.emplace_back(this->coins[j].C + this->params->get_G().inverse()*Scalar(this->coins[j].v));
		value_witness.emplace_back(SparkUtils::hash_val(k));
	}

	// Complete the value proof
	schnorr.prove(value_witness, value_statement, this->value_proof);
}

bool MintTransaction::verify() {
	// Verify the value proof
	Schnorr schnorr(this->params->get_H());
	std::vector<GroupElement> value_statement;

	for (std::size_t j = 0; j < this->coins.size(); j++) {
		value_statement.emplace_back(this->coins[j].C + this->params->get_G().inverse()*Scalar(this->coins[j].v));
	}

	return schnorr.verify(value_statement, this->value_proof);
}

}
