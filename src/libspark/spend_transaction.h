#ifndef FIRO_SPARK_SPEND_TRANSACTION_H
#define FIRO_SPARK_SPEND_TRANSACTION_H
#include "keys.h"
#include "coin.h"
#include "schnorr.h"
#include "util.h"
#include "grootle.h"
#include "bpplus.h"
#include "chaum.h"

namespace spark {

using namespace secp_primitives;

// Note that cover sets are treated as monotonic, meaning they grow over time (up to some implementation-defined limit)
// To support efficient batching, we track which set each spend references
// If spends share a `cover_set_id`, we assume the corresponding `cover_set` vectors have a subset relationship
// This relationship _must_ be checked elsewhere, as we simply use the largest `cover_set` for each `cover_set_id`!
struct InputCoinData {
    uint64_t cover_set_id; // an identifier for the monotonically-growing set of which `cover_set` is a subset
    std::size_t index; // index of the coin in the cover set
    Scalar s; // serial number
    GroupElement T; // tag
    uint64_t v; // value
    Scalar k; // nonce
    Scalar a;            // asset type
    Scalar iota;         // identifier
};

struct CoverSetData {
    std::size_t cover_set_size; // set of coins used as a cover set for the spend
    std::vector<unsigned char> cover_set_representation; // a unique representation for the ordered elements of the partial `cover_set` used in the spend
};

struct OutputCoinData {
    Address address;
    uint64_t v;
    std::string memo;
    Scalar a;    // asset type
    Scalar iota; // identifier
};

class BaseSpendTransaction {
public:
    virtual ~BaseSpendTransaction() = default;
    virtual void setOutCoins(const std::vector<Coin>& out_coins_) = 0;
    virtual void setCoverSets(const std::unordered_map<uint64_t, CoverSetData>& cover_set_data) = 0;
    virtual void setVout(const uint64_t& vout_) = 0;
    virtual const std::vector<GroupElement>& getUsedLTags() const = 0;
    virtual bool isSpats() const = 0;
    virtual const std::map<uint64_t, uint256>& getBlockHashes() = 0;
    virtual const std::vector<uint64_t>& getCoinGroupIds() = 0;
    virtual void setBurn(const uint64_t& burn_) = 0;
};

class SpendTransaction : public BaseSpendTransaction {
public:
    SpendTransaction(
        const Params* params);

    SpendTransaction(
	const Params* params,
	const FullViewKey& full_view_key,
	const SpendKey& spend_key,
	const std::vector<InputCoinData>& inputs,
        const std::unordered_map<uint64_t, CoverSetData>& cover_set_data,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets,
        const uint64_t f,
        const uint64_t vout,
	const std::vector<OutputCoinData>& outputs
    );

    ~SpendTransaction();

    uint64_t getFee();
    const std::vector<GroupElement>& getUsedLTags() const override;
    const std::vector<Coin>& getOutCoins();
    const std::vector<uint64_t>& getCoinGroupIds() override;

    static bool verify(const Params* params, const std::vector<SpendTransaction>& transactions, const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets);
    static bool verify(const SpendTransaction& transaction, const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets);
    
    static std::vector<unsigned char> hash_bind_inner(
        const std::map<uint64_t, std::vector<unsigned char>>& cover_set_representations,
        const std::vector<GroupElement>& S1,
        const std::vector<GroupElement>& C1,
        const std::vector<GroupElement>& T,
        const std::vector<GrootleProof>& grootle_proofs,
        const SchnorrProof& balance_proof,
	const BPPlusProof& range_proof
    );
    static Scalar hash_bind(
        const std::vector<unsigned char> hash_bind_inner,
        const std::vector<Coin>& out_coins,
        const uint64_t f_
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
        READWRITE(balance_proof);
        READWRITE(range_proof);
    }

    void setOutCoins(const std::vector<Coin>& out_coins_) override {
        this->out_coins = out_coins_;
    }

    void setCoverSets(const std::unordered_map<uint64_t, CoverSetData>& cover_set_data) override {
        for (const auto& data : cover_set_data) {
            this->cover_set_sizes[data.first] = data.second.cover_set_size;
            this->cover_set_representations[data.first] = data.second.cover_set_representation;
        }
    }

    bool isSpats() const override {
        return false;
    }

    void setVout(const uint64_t& vout_) override {
        this->vout = vout_;
    }

    void setBurn(const uint64_t& burn_) override {}

    void setBlockHashes(const std::map<uint64_t, uint256>& idAndHashes);

    const std::map<uint64_t, uint256>& getBlockHashes() override;
private:
    const Params* params;
    // We need to construct and pass this data before running verification
    std::unordered_map<uint64_t, std::size_t> cover_set_sizes;
    std::map<uint64_t, std::vector<unsigned char>> cover_set_representations;
    std::vector<Coin> out_coins;

    // All this data we need to serialize
    std::map<uint64_t, uint256> set_id_blockHash;
    std::vector<uint64_t> cover_set_ids;
    uint64_t f;
    uint64_t vout;
    std::vector<GroupElement> S1, C1, T;
    std::vector<GrootleProof> grootle_proofs;
    ChaumProof chaum_proof;
    SchnorrProof balance_proof;
    BPPlusProof range_proof;
};

}

#endif
