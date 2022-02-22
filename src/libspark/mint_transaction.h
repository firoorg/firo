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
	MintTransaction(
		const Params* params,
		const std::vector<MintedCoinData>& outputs
	);
	bool verify();

private:
	const Params* params;
	std::vector<Coin> coins;
	std::vector<SchnorrProof> value_proofs;
};

}

#endif
