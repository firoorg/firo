#ifndef FIRO_SPATS_MINT_TRANSACTION_H
#define FIRO_SPATS_MINT_TRANSACTION_H
#include "coin.h"
#include "keys.h"
#include "schnorr.h"
#include "util.h"

namespace spats
{

using namespace secp_primitives;

struct MintedCoinData {
    Address address;
    uint64_t v;
    Scalar a;
    Scalar iota;
    std::string memo;
};

class MintTransaction
{
public:
    MintTransaction(const Params* params);
    MintTransaction(
        const Params* params,
        const std::vector<MintedCoinData>& outputs,
        const std::vector<unsigned char>& serial_context,
        bool generate = true);
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

} // namespace spats

#endif
