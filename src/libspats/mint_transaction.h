#ifndef FIRO_SPATS_MINT_TRANSACTION_H
#define FIRO_SPATS_MINT_TRANSACTION_H
#include "coin.h"
#include "../libspark/keys.h"
#include "../libspark/schnorr.h"
#include "util.h"

namespace spats
{

using namespace secp_primitives;

struct MintedCoinData {
    spark::Address address;
    uint64_t v;
    Scalar a;
    Scalar iota;
    std::string memo;
};

class MintTransaction
{
public:
    MintTransaction(const spark::Params* params);
    MintTransaction(
        const spark::Params* params,
        const std::vector<MintedCoinData>& outputs,
        const std::vector<unsigned char>& serial_context,
        bool generate = true);
    bool verify();

    // returns the vector of serialized coins, with first one it puts also the Schnorr proof;
    std::vector<CDataStream> getMintedCoinsSerialized();

    // deserialize from the vector of CDataStreams
    void setMintTransaction(std::vector<CDataStream>& serializedCoins);

    void getCoins(std::vector<Coin>& coins_);

private:
    const spark::Params* params;
    std::vector<Coin> coins;
    spark::SchnorrProof value_proof;
};

} // namespace spats

#endif
