#include "mint_transaction.h"

namespace spark {

MintTransaction::MintTransaction(
	const Params* params,
	const std::vector<MintedCoinData>& outputs,
    bool generate
) {
	// Important note: This construction assumes that the public coin values are correct according to higher-level consensus rules!
	this->params = params;
	Schnorr schnorr(this->params->get_H());

	std::vector<GroupElement> value_statement;
	std::vector<Scalar> value_witness;

	for (std::size_t j = 0; j < outputs.size(); j++) {
        if (generate) {
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

            // Prepare the value proof
            value_statement.emplace_back(this->coins[j].C + this->params->get_G().inverse()*Scalar(this->coins[j].v));
            value_witness.emplace_back(SparkUtils::hash_val(k));
        } else {
            this->coins.emplace_back(Coin());
        }
	}

	// Complete the value proof
    if (generate)
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

std::vector<CDataStream> MintTransaction::getMintedCoinsSerialized() {
    std::vector<CDataStream> serializedCoins;
    bool first = true;
    for (const auto& coin : coins) {
        CDataStream serializedCoin(SER_NETWORK, 0);
        serializedCoin << coin;
        if (first) {
            serializedCoin << value_proof;
            first = false;
        }
        serializedCoins.push_back(serializedCoin);
    }
    return serializedCoins;
}

void MintTransaction::getCoins(std::vector<Coin>& coins_) {
    coins_.insert(coins_.end(), coins.begin(), coins.end());
}


} // namespace spark
