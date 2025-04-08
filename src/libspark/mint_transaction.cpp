#include "mint_transaction.h"

namespace spark {

MintTransaction::MintTransaction(const Params* params) {
    this->params = params;
}

MintTransaction::MintTransaction(
	const Params* params,
	const std::vector<MintedCoinData>& outputs,
	const std::vector<unsigned char>& serial_context,
    bool generate
) {
	// Important note: This construction assumes that the public coin values are correct according to higher-level consensus rules!
	// Important note: For pool transition transactions, the serial context should contain unique references to all base-layer spent assets, in order to ensure the resulting serial commitment is bound to this transaction

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
                output.memo,
                serial_context
            ));

            // Prepare the value proof
            value_statement.emplace_back(this->coins[j].C + this->params->get_G().inverse()*Scalar(this->coins[j].v));
            value_witness.emplace_back(SparkUtils::hash_val(k));
        } else {
            Coin coin(params);
            coin.type = 0;
            coin.r_.ciphertext.resize(82); // max possible size
            coin.r_.key_commitment.resize(32);
            coin.r_.tag.resize(16);
            coin.v = 0;
            this->coins.emplace_back(coin);
        }
	}

	// Complete the value proof
    if (generate)
	    schnorr.prove(value_witness, value_statement, this->value_proof);
    else
        value_proof = SchnorrProof();
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

void MintTransaction::setMintTransaction(std::vector<CDataStream>& serializedCoins) {
    bool first = true;
    coins.reserve(serializedCoins.size());
    [[maybe_unused]] size_t i = 0;
    for (auto& stream : serializedCoins) {
        Coin coin(params);
        stream >> coin;
        coins.push_back(coin);
        i++;
        if (first) {
            stream >> value_proof;
            first = false;
        }
    }
}

void MintTransaction::getCoins(std::vector<Coin>& coins_) {
    coins_.insert(coins_.end(), coins.begin(), coins.end());
}


} // namespace spark
