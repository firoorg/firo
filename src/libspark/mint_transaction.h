#ifndef FIRO_SPARK_MINT_TRANSACTION_H
#define FIRO_SPARK_MINT_TRANSACTION_H
#include "keys.h"
#include "coin.h"
#include "schnorr.h"
#include "util.h"

namespace spark {

using namespace secp_primitives;

class MintTransaction {
public:
	MintTransaction(
		const Params* params,
		const Address& address,
		uint64_t v,
		const std::string memo
	);
	bool verify();

private:
	const Params* params;
	Coin coin;
	SchnorrProof balance_proof;
};

}

#endif
