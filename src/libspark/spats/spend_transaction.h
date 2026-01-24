#ifndef FIRO_SPATS_SPEND_TRANSACTION_H
#define FIRO_SPATS_SPEND_TRANSACTION_H
#include "balance.h"
#include "base_asset.h"
#include "bpplus.h"
#include "../chaum.h"
#include "../grootle.h"
#include "../keys.h"
#include "../schnorr.h"
#include "../coin.h"
#include "../spend_transaction.h"
#include "type.h"
#include "util.h"
#include <algorithm>


namespace spats
{

using namespace secp_primitives;

// Note that cover sets are treated as monotonic, meaning they grow over time (up to some implementation-defined limit)
// To support efficient batching, we track which set each spend references
// If spends share a `cover_set_id`, we assume the corresponding `cover_set` vectors have a subset relationship
// This relationship _must_ be checked elsewhere, as we simply use the largest `cover_set` for each `cover_set_id`!
class SpendTransaction : public spark::BaseSpendTransaction
{
public:
    SpendTransaction(
        const spark::Params* params);

    SpendTransaction(
        const spark::Params* params,
        const spark::FullViewKey& full_view_key,
        const spark::SpendKey& spend_key,
        const std::vector<spark::InputCoinData>& inputs,//should be sorted, base coins at the beginning, otherwise you will get a failure
        const std::unordered_map<uint64_t, spark::CoverSetData>& cover_set_data,
        const std::unordered_map<uint64_t, std::vector<spark::Coin>>& cover_sets,
        uint64_t f,
        uint64_t vout,
        uint64_t burn,
        const std::vector<spark::OutputCoinData>& outputs); //should be sorted, base coins at the beginning, otherwise you will get a failure

    ~SpendTransaction();

    uint64_t getFee();
    const std::vector<GroupElement>& getUsedLTags() const override;
    const std::vector<spark::Coin>& getOutCoins();
    const std::vector<uint64_t>& getCoinGroupIds() override;

    static bool verify(const spark::Params* params, const std::vector<SpendTransaction>& transactions, const std::unordered_map<uint64_t, std::vector<spark::Coin> >& cover_sets);
    static bool verify(const SpendTransaction& transaction, const std::unordered_map<uint64_t, std::vector<spark::Coin> >& cover_sets);

    static std::vector<unsigned char> hash_bind_inner(
        const std::map<uint64_t, std::vector<unsigned char> >& cover_set_representations,
        const std::vector<GroupElement>& S1,
        const std::vector<GroupElement>& C1,
        const std::vector<GroupElement>& T,
        const std::vector<spark::GrootleProof>& grootle_proofs,
        const spark::SchnorrProof& rep_proof,
        const BPPlusProof& range_proof,
        const BaseAssetProof& base_proof,
        const TypeProof& type_proof,
        const BalanceProof& balance_proof,
        bool include_asset_proofs = true
    );
    static Scalar hash_bind(
        const std::vector<unsigned char>& hash_bind_inner,
        const std::vector<spark::Coin>& out_coins,
        uint64_t f_,
        uint64_t burn
        );

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(cover_set_ids);
        READWRITE(set_id_blockHash);
        READWRITE(f);
        READWRITE(S1);
        READWRITE(C1);
        READWRITE(T);
        READWRITE(grootle_proofs);
        READWRITE(chaum_proof);
        READWRITE(range_proof);
        READWRITE(rep_proof);
        READWRITE(inputBase);
        READWRITE(outBase);
        READWRITE(base_proof);
        // Only serialize type_proof and balance_proof if there are asset (non-base) inputs
        bool has_asset_inputs = (inputBase < C1.size());
        if (has_asset_inputs) {
            READWRITE(type_proof);
            READWRITE(balance_proof);
        }
    }

    void setOutCoins(const std::vector<spark::Coin>& out_coins_) override {
        this->out_coins = out_coins_;
    }

    void setCoverSets(const std::unordered_map<uint64_t, spark::CoverSetData>& cover_set_data)override {
        for (const auto& data : cover_set_data) {
            this->cover_set_sizes[data.first] = data.second.cover_set_size;
            this->cover_set_representations[data.first] = data.second.cover_set_representation;
        }
    }

    void setVout(const uint64_t& vout_) override {
        this->vout = vout_;
    }

    void setBurn(const uint64_t& burn_) override {
        this->burn = burn_;
    }

    bool isSpats() const override {
        return true;
    }

    void setBlockHashes(const std::map<uint64_t, uint256>& idAndHashes);

    const std::map<uint64_t, uint256>& getBlockHashes() override;

private:
    const spark::Params* params;
    // We need to construct and pass this data before running verification
    std::unordered_map<uint64_t, std::size_t> cover_set_sizes;
    std::map<uint64_t, std::vector<unsigned char> > cover_set_representations;
    std::vector<spark::Coin> out_coins;
    uint64_t vout = 0;
    uint64_t burn = 0;

    // All this data we need to serialize
    std::map<uint64_t, uint256> set_id_blockHash;
    uint32_t inputBase;
    uint32_t outBase;
    std::vector<uint64_t> cover_set_ids;
    uint64_t f;
    std::vector<GroupElement> S1, C1, T;
    std::vector<spark::GrootleProof> grootle_proofs;
    spark::ChaumProof chaum_proof;
    spark::SchnorrProof rep_proof;
    BPPlusProof range_proof;
    BaseAssetProof base_proof;
    TypeProof type_proof;
    BalanceProof balance_proof;
};

} // namespace spats

#endif
