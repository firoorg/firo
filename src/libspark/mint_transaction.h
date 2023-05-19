#ifndef FIRO_SPARK_MINT_TRANSACTION_H
#define FIRO_SPARK_MINT_TRANSACTION_H
#include "keys.h"
#include "coin.h"
#include "schnorr.h"
#include "util.h"

namespace spark {

using namespace secp_primitives;

struct MintedCoinData {
	Address address;
	uint64_t v;
	std::string memo;
};

class MintTransaction {
public:
    MintTransaction(const Params* params);
	MintTransaction(
		const Params* params,
		const std::vector<MintedCoinData>& outputs,
		const std::vector<unsigned char>& serial_context,
		bool generate = true
	);
	bool verify();

    // returns the vector of serialized coins, with first one it puts also the chnorr proof;
    std::vector<CDataStream> getMintedCoinsSerialized();

    // deserialize from the vector of CDataStreams
    void setMintTransaction(std::vector<CDataStream>& serializedCoins);

    void getCoins(std::vector<Coin>& coins_);

private:
	const Params* params;
	std::vector<Coin> coins;
	SchnorrProof value_proof;
};

}

#endif
