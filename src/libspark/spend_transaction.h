#ifndef FIRO_SPARK_SPEND_TRANSACTION_H
#define FIRO_SPARK_SPEND_TRANSACTION_H


#include <algorithm>
#include <limits>
#include <random>
#include <set>

#include "grootle_proof.h"
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
};

struct CoverSetData {
    std::size_t cover_set_size; // set of coins used as a cover set for the spend
    std::vector<unsigned char> cover_set_representation; // a unique representation for the ordered elements of the partial `cover_set` used in the spend
};

struct OutputCoinData {
	Address address;
	uint64_t v;
	std::string memo;
};

enum class SpendTransactionVersion : uint8_t {
    V1 = 1,
    V2 = 2,
};

static constexpr std::size_t MAX_SPARK_V2_OUTPUTS = 16;

class SpendTransaction {
public:
    SpendTransaction(
        const Params* params,
        SpendTransactionVersion version = SpendTransactionVersion::V1,
        std::size_t expected_output_count = 0);

	SpendTransaction(
		const Params* params,
		const FullViewKey& full_view_key,
		const SpendKey& spend_key,
		const std::vector<InputCoinData>& inputs,
        const std::unordered_map<uint64_t, CoverSetData>& cover_set_data,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets,
		const uint64_t f,
		const uint64_t vout,
        const std::vector<OutputCoinData>& outputs,
        SpendTransactionVersion version = SpendTransactionVersion::V1,
        const uint256& extension_commitment = uint256(),
        const std::map<uint64_t, uint256>& block_hashes = {}
	);

	uint64_t getFee();
    SpendTransactionVersion getVersion() const { return version; }
    const std::vector<GroupElement>& getUsedLTags() const;
    const std::vector<Coin>& getOutCoins();
    const std::vector<uint64_t>& getCoinGroupIds();
    const uint256& getExtensionCommitment() const {
        return extension_commitment;
    }

	static bool verify(const Params* params, const std::vector<SpendTransaction>& transactions, const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets);
	static bool verify(const SpendTransaction& transaction, const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets);
    static bool verifyHistorical(
        const Params* params,
        const std::vector<SpendTransaction>& transactions,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets);
    static bool verifyHistorical(
        const SpendTransaction& transaction,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets);
    
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
        if (version == SpendTransactionVersion::V2) {
            SerializationOpV2(s, ser_action);
            return;
        }

        // CHAUM_V1 is the historical deployed layout. Do not add a version
        // byte or otherwise alter these bytes.
        READWRITE(cover_set_ids);
        READWRITE(set_id_blockHash);
        READWRITE(f);
        READWRITE(S1);
        READWRITE(C1);
        READWRITE(T);
        READWRITE(grootle_proofs);
        READWRITE(chaum_proof_v1);
        READWRITE(balance_proof);
        READWRITE(range_proof);
    }

    void setOutCoins(const std::vector<Coin>& out_coins_) {
        if (version == SpendTransactionVersion::V2 &&
            out_coins_.size() != expected_output_count) {
            throw std::invalid_argument("Spark V2 output count mismatch");
        }
        this->out_coins = out_coins_;
    }

    void setCoverSets(const std::unordered_map<uint64_t, CoverSetData>& cover_set_data) {
        for (const auto& data : cover_set_data) {
            this->cover_set_sizes[data.first] = data.second.cover_set_size;
            this->cover_set_representations[data.first] = data.second.cover_set_representation;
        }
    }

    void setVout(const uint64_t& vout_) {
        // Defense-in-depth: guard against uint64_t overflow of fee + vout
        if (vout_ > 0 && this->f > std::numeric_limits<uint64_t>::max() - vout_) {
            throw std::invalid_argument("fee + vout overflow");
        }
        this->vout = vout_;
    }

    void setBlockHashes(const std::map<uint64_t, uint256>& idAndHashes);

    const std::map<uint64_t, uint256>& getBlockHashes();
private:
	template <typename Stream, typename Operation, typename T>
    void ReadWriteFixedVector(
        Stream& s,
        Operation ser_action,
        std::vector<T>& values,
        const std::size_t expected_size)
    {
        if (ser_action.ForRead()) {
            values.resize(expected_size);
        } else if (values.size() != expected_size) {
            throw std::ios_base::failure("wrong Spark V2 vector size");
        }
        for (auto& value : values) {
            READWRITE(value);
        }
    }

    template <typename Stream, typename Operation>
    void SerializationOpV2(Stream& s, Operation ser_action)
    {
        uint8_t wire_version = static_cast<uint8_t>(SpendTransactionVersion::V2);
        READWRITE(wire_version);
        if (wire_version != static_cast<uint8_t>(SpendTransactionVersion::V2)) {
            throw std::ios_base::failure("unsupported Spark spend proof version");
        }

        uint64_t input_count = cover_set_ids.size();
        uint64_t output_count = expected_output_count;
        if (ser_action.ForRead()) {
            input_count = ReadCompactSize(s);
            output_count = ReadCompactSize(s);
        } else {
            WriteCompactSize(s, input_count);
            WriteCompactSize(s, output_count);
        }
        if (input_count == 0 || input_count > MAX_CHAUM_V2_INPUTS ||
            output_count == 0 || output_count > MAX_SPARK_V2_OUTPUTS ||
            (ser_action.ForRead() && output_count != expected_output_count)) {
            throw std::ios_base::failure("bad Spark V2 dimensions");
        }

        ReadWriteFixedVector(s, ser_action, cover_set_ids, input_count);

        uint64_t block_hash_count = set_id_blockHash.size();
        if (ser_action.ForRead()) {
            block_hash_count = ReadCompactSize(s);
            set_id_blockHash.clear();
        } else {
            WriteCompactSize(s, block_hash_count);
        }
        if (block_hash_count > input_count) {
            throw std::ios_base::failure("too many Spark V2 cover-set hashes");
        }
        uint64_t previous_id = 0;
        for (uint64_t i = 0; i < block_hash_count; ++i) {
            uint64_t id;
            uint256 block_hash;
            if (ser_action.ForRead()) {
                READWRITE(id);
                READWRITE(block_hash);
                if ((i != 0 && id <= previous_id) ||
                    !set_id_blockHash.emplace(id, block_hash).second) {
                    throw std::ios_base::failure("non-canonical Spark V2 cover-set map");
                }
                previous_id = id;
            } else {
                const auto& entry = *std::next(set_id_blockHash.begin(), i);
                id = entry.first;
                block_hash = entry.second;
                READWRITE(id);
                READWRITE(block_hash);
            }
        }
        for (const auto& entry : set_id_blockHash) {
            if (std::find(
                    cover_set_ids.begin(), cover_set_ids.end(), entry.first) ==
                    cover_set_ids.end()) {
                throw std::ios_base::failure(
                    "Spark V2 cover-set hash has no input");
            }
        }
        for (uint64_t id : cover_set_ids) {
            if (set_id_blockHash.count(id) == 0) {
                throw std::ios_base::failure(
                    "Spark V2 input has no cover-set hash");
            }
        }

        READWRITE(f);
        READWRITE(extension_commitment);
        ReadWriteFixedVector(s, ser_action, S1, input_count);
        ReadWriteFixedVector(s, ser_action, C1, input_count);
        ReadWriteFixedVector(s, ser_action, T, input_count);

        if (ser_action.ForRead()) {
            grootle_proofs.resize(input_count);
        } else if (grootle_proofs.size() != input_count) {
            throw std::ios_base::failure("wrong Spark V2 Grootle proof count");
        }
        const std::size_t m = params->get_m_grootle();
        const std::size_t f_size = m*(params->get_n_grootle() - 1);
        for (auto& proof : grootle_proofs) {
            READWRITE(proof.A);
            READWRITE(proof.B);
            ReadWriteFixedVector(s, ser_action, proof.X, m);
            ReadWriteFixedVector(s, ser_action, proof.X1, m);
            ReadWriteFixedVector(s, ser_action, proof.f, f_size);
            READWRITE(proof.z);
            READWRITE(proof.zS);
            READWRITE(proof.zV);
        }

        ReadWriteFixedVector(s, ser_action, chaum_proof_v2.A1, input_count);
        ReadWriteFixedVector(s, ser_action, chaum_proof_v2.A2, input_count);
        ReadWriteFixedVector(s, ser_action, chaum_proof_v2.t1, input_count);
        ReadWriteFixedVector(s, ser_action, chaum_proof_v2.t2, input_count);
        ReadWriteFixedVector(s, ser_action, chaum_proof_v2.t3, input_count);

        READWRITE(balance_proof);

        std::size_t padded_outputs = 1;
        while (padded_outputs < output_count) {
            padded_outputs <<= 1;
        }
        std::size_t rounds = 0;
        for (std::size_t inner_product_size = 64*padded_outputs;
             inner_product_size > 1;
             inner_product_size >>= 1) {
            ++rounds;
        }
        READWRITE(range_proof.A);
        READWRITE(range_proof.A1);
        READWRITE(range_proof.B);
        READWRITE(range_proof.r1);
        READWRITE(range_proof.s1);
        READWRITE(range_proof.d1);
        ReadWriteFixedVector(s, ser_action, range_proof.L, rounds);
        ReadWriteFixedVector(s, ser_action, range_proof.R, rounds);
    }

	static bool verify(
        const Params* params,
        const std::vector<SpendTransaction>& transactions,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets,
		bool require_single_input);

    static ChaumV2Context GetChaumV2Context(
        const std::vector<Coin>& out_coins,
        uint64_t fee,
        uint64_t transparent_value,
        const uint256& extension_commitment,
        const std::vector<uint64_t>& cover_set_ids,
        const std::map<uint64_t, uint256>& block_hashes);

	const Params* params;
    SpendTransactionVersion version;
    std::size_t expected_output_count;
    // We need to construct and pass this data before running verification
	std::unordered_map<uint64_t, std::size_t> cover_set_sizes;
    std::map<uint64_t, std::vector<unsigned char>> cover_set_representations;
	std::vector<Coin> out_coins;

    // All this data we need to serialize
    std::map<uint64_t, uint256> set_id_blockHash;
    std::vector<uint64_t> cover_set_ids;
	uint64_t f;
    uint64_t vout;
    uint256 extension_commitment;
	std::vector<GroupElement> S1, C1, T;
	std::vector<GrootleProof> grootle_proofs;
	ChaumProofV1 chaum_proof_v1;
	ChaumProofV2 chaum_proof_v2;
	SchnorrProof balance_proof;
	BPPlusProof range_proof;
};

}

#endif
