#ifndef FIRO_SPARK_COIN_H
#define FIRO_SPARK_COIN_H
#include "bpplus.h"
#include "keys.h"
#include <math.h>
#include "params.h"
#include "aead.h"
#include "util.h"
#include "../uint256.h"
#include "crypto/sha256.h"
#include "primitives/mint_spend.h"

namespace spark {

using namespace secp_primitives;

// Flags for coin types: those generated from mints, and those generated from spends
const char COIN_TYPE_MINT = 0;
const char COIN_TYPE_SPEND = 1;

struct IdentifiedCoinData {
	uint64_t i; // diversifier
	std::vector<unsigned char> d; // encrypted diversifier
	uint64_t v; // value
	Scalar k; // nonce
	std::string memo; // memo
};

struct RecoveredCoinData {
	Scalar s; // serial
	GroupElement T; // tag
};

// Data to be encrypted for the recipient of a coin generated in a mint transaction
struct MintCoinRecipientData {
	std::vector<unsigned char> d; // encrypted diversifier
	Scalar k; // nonce
	std::string padded_memo; // padded memo with prepended one-byte length

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(d);
		READWRITE(k);
		READWRITE(padded_memo);
    }
};

// Data to be encrypted for the recipient of a coin generated in a spend transaction
struct SpendCoinRecipientData {
	uint64_t v; // value
	std::vector<unsigned char> d; // encrypted diversifier
	Scalar k; // nonce
	std::string padded_memo; // padded memo with prepended one-byte length

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(v);
        READWRITE(d);
		READWRITE(k);
		READWRITE(padded_memo);
    }
};

class Coin {
public:
	Coin();
    Coin(const Params* params);
	Coin(
		const Params* params,
		const char type,
		const Scalar& k,
		const Address& address,
		const uint64_t& v,
		const std::string& memo,
		const std::vector<unsigned char>& serial_context
	);

	// Given an incoming view key, extract the coin's nonce, diversifier, value, and memo
	IdentifiedCoinData identify(const IncomingViewKey& incoming_view_key);

	// Given a full view key, extract the coin's serial number and tag
	RecoveredCoinData recover(const FullViewKey& full_view_key, const IdentifiedCoinData& data);

    static std::size_t memoryRequired();

    bool operator==(const Coin& other) const;
    bool operator!=(const Coin& other) const;

    // type and v are not included in hash
    uint256 getHash() const;

    void setParams(const Params* params);
    void setSerialContext(const std::vector<unsigned char>& serial_context_);
protected:
	bool validate(const IncomingViewKey& incoming_view_key, IdentifiedCoinData& data);

public:
	const Params* params;
	char type; // type flag
	GroupElement S, K, C; // serial commitment, recovery key, value commitment
	AEADEncryptedData r_; // encrypted recipient data
	uint64_t v; // value
	std::vector<unsigned char> serial_context; // context to which the serial commitment should be bound (not serialized, but inferred)

	// Serialization depends on the coin type
	ADD_SERIALIZE_METHODS;
	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action) {
		// The type must be valid
		READWRITE(type);
		if (type != COIN_TYPE_MINT && type != COIN_TYPE_SPEND) {
			throw std::invalid_argument("Cannot deserialize coin due to bad type");
		}
		READWRITE(S);
		READWRITE(K);
		READWRITE(C);

		// Encrypted coin data is always of a fixed size that depends on coin type
		// Its tag and key commitment sizes are enforced during its deserialization
		// For mint coins: encrypted diversifier (with size), encoded nonce, padded memo (with size), unpadded memo length
		// For spend coins: encoded value, encrypted diversifier (with size), encoded nonce, padded memo (with size), unpadded memo length
		READWRITE(r_);
		if (ser_action.ForRead()) {
			this->params = spark::Params::get_default();
		}
		if (type == COIN_TYPE_MINT && r_.ciphertext.size() != (1 + AES_BLOCKSIZE) + SCALAR_ENCODING + (1 + params->get_memo_bytes() + 1)) {
			throw std::invalid_argument("Cannot deserialize mint coin due to bad encrypted data");
		}
		if (type == COIN_TYPE_SPEND && r_.ciphertext.size() != 8 + (1 + AES_BLOCKSIZE) + SCALAR_ENCODING + (1 + params->get_memo_bytes() + 1)) {
			throw std::invalid_argument("Cannot deserialize spend coin due to bad encrypted data");
		}

		if (type == COIN_TYPE_MINT) {
			READWRITE(v);
		}
	}
};

} // namespace spark

// keep this just to not break old index (chain index serialization)
namespace sigma {
enum class CoinDenomination : std::uint8_t {
    SIGMA_DENOM_0_05 = 5,
    SIGMA_DENOM_0_1 = 0,
    SIGMA_DENOM_0_5 = 1,
    SIGMA_DENOM_1 = 2,
    SIGMA_DENOM_10 = 3,
    SIGMA_DENOM_25 = 6,
    SIGMA_DENOM_100 = 4
};
// Serialization support for CoinDenomination

template<typename Stream>
void Serialize(Stream& os, CoinDenomination d)
{
    Serialize(os, static_cast<std::uint8_t>(d));
}

template<typename Stream>
void Unserialize(Stream& is, CoinDenomination& d)
{
    std::uint8_t v;
    Unserialize(is, v);
    d = static_cast<CoinDenomination>(v);
}

class PublicCoin {
public:
    PublicCoin() {}
    template<typename Stream>
    inline void Serialize(Stream& s) const {
        constexpr int size = secp_primitives::GroupElement::memoryRequired();
        unsigned char buffer[size + sizeof(int32_t)];
        value.serialize(buffer);
        int32_t denom32 = static_cast<int32_t>(static_cast<std::uint8_t>(denomination));
        std::memcpy(buffer + size, &denom32, sizeof(denom32));
        char* b = (char*)buffer;
        s.write(b, size + sizeof(int32_t));
    }

    template<typename Stream>
    inline void Unserialize(Stream& s) {
        constexpr int size = secp_primitives::GroupElement::memoryRequired();
        unsigned char buffer[size + sizeof(int32_t)];
        char* b = (char*)buffer;
        s.read(b, size + sizeof(int32_t));
        value.deserialize(buffer);
        int32_t denom32;
        std::memcpy(&denom32, buffer + size, sizeof(denom32));
        denomination = static_cast<CoinDenomination>(static_cast<std::uint8_t>(denom32));
    }

private:
    secp_primitives::GroupElement value;
    CoinDenomination denomination;
};

struct CSpendCoinInfo {
    CoinDenomination denomination;
    int coinGroupId;

    template<typename Stream>
    void Serialize(Stream& s) const {
        int64_t tmp = uint8_t(denomination);
        s << tmp;
        tmp = coinGroupId;
        s << tmp;
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        int64_t tmp;
        s >> tmp; denomination = CoinDenomination(tmp);
        s >> tmp; coinGroupId = int(tmp);
    }

};

struct CScalarHash {
    std::size_t operator ()(const secp_primitives::Scalar& bn) const noexcept {
        std::vector<unsigned char> bnData(bn.memoryRequired());
        bn.serialize(&bnData[0]);
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(&bnData[0], bnData.size()).Finalize(hash);
        // take the first bytes of "hash".
        std::size_t result;
        std::memcpy(&result, hash, sizeof(std::size_t));
        return result;
    }
};

using spend_info_container = std::unordered_map<secp_primitives::Scalar, CSpendCoinInfo, CScalarHash>;

}

namespace lelantus {

using namespace secp_primitives;

// Stub for chain index serialization only (Lelantus protocol removed).
class PublicCoin {
public:
    PublicCoin() : value() {}
    PublicCoin(const GroupElement& coin) : value(coin) {}

    const GroupElement& getValue() const { return value; }
    uint256 getValueHash() const { return primitives::GetPubCoinValueHash(value); }
    bool operator==(const PublicCoin& other) const { return value == other.value; }
    bool operator!=(const PublicCoin& other) const { return !(*this == other); }
    bool validate() const { return value.isMember() && !value.isInfinity(); }
    size_t GetSerializeSize() const { return value.memoryRequired(); }

    template<typename Stream>
    inline void Serialize(Stream& s) const {
        std::vector<unsigned char> buffer(GetSerializeSize());
        value.serialize(buffer.data());
        s.write((const char *)buffer.data(), buffer.size());
    }

    template<typename Stream>
    inline void Unserialize(Stream& s) {
        std::vector<unsigned char> buffer(GetSerializeSize());
        s.read((char *)buffer.data(), buffer.size());
        value.deserialize(buffer.data());
    }

private:
    GroupElement value;
};

} // namespace lelantus

#endif
