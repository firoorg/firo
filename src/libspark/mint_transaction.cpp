#include "mint_transaction.h"

namespace spark {

MintTransaction::MintTransaction(
	const Params* params,
	const Address& address,
	uint64_t v,
	const std::string memo
) {
	this->params = params;

	// Generate the coin
	Scalar k;
	k.randomize();
	this->coin = Coin(
		this->params,
		COIN_TYPE_MINT,
		k,
		address,
		v,
		memo
	);

	// Generate the balance proof
	Schnorr schnorr(this->params->get_H());
	schnorr.prove(
		SparkUtils::hash_val(k),
		this->coin.C + this->params->get_G().inverse()*Scalar(v),
		this->balance_proof
	);
}

bool MintTransaction::verify() {
	// Verify the balance proof
	Schnorr schnorr(this->params->get_H());
	return schnorr.verify(
		this->coin.C + this->params->get_G().inverse()*Scalar(this->coin.v),
		this->balance_proof
	);
}

}
