#ifndef FIRO_SPARK_COIN_H
#define FIRO_SPARK_COIN_H
#include "bpplus.h"
#include "keys.h"
#include <math.h>
#include "params.h"
#include "aead.h"
#include "util.h"
#include "../uint256.h"

namespace spark {

using namespace secp_primitives;

// Flags for coin types: those generated from mints, and those generated from spends
const char COIN_TYPE_MINT = 0;
const char COIN_TYPE_SPEND = 1;
const char COIN_TYPE_MINT_V2 = 2;
const char COIN_TYPE_SPEND_V2 = 3;

struct IdentifiedCoinData {
    uint64_t i; // diversifier
    std::vector<unsigned char> d; // encrypted diversifier
    uint64_t v; // value
    Scalar k; // nonce
    std::string memo; // memo
    Scalar a = Scalar(uint64_t(0));     // asset type
    Scalar iota = Scalar(uint64_t(0));  // identifier
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
	char type; // type flag
	uint64_t v; // value
	std::vector<unsigned char> d; // encrypted diversifier
	Scalar k; // nonce
	std::string padded_memo; // padded memo with prepended one-byte length
	Scalar a;                     // asset type
	Scalar iota;                  // identifier

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(v);
        READWRITE(d);
		READWRITE(k);
		READWRITE(padded_memo);
        if (type > COIN_TYPE_SPEND) {
            READWRITE(a);
            READWRITE(iota);
        }
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
		const std::vector<unsigned char>& serial_context,
		const Scalar& a = Scalar(uint64_t(0)),
		const Scalar& iota = Scalar(uint64_t(0))
	);

	// Given an incoming view key, extract the coin's nonce, diversifier, value, and memo
	IdentifiedCoinData identify(const IncomingViewKey& incoming_view_key);

	// Given a full view key, extract the coin's serial number and tag
	RecoveredCoinData recover(const FullViewKey& full_view_key, const IdentifiedCoinData& data);

    static std::size_t memoryRequired();
    static std::size_t memoryRequiredSpats();

    bool operator==(const Coin& other) const;
    bool operator!=(const Coin& other) const;

    // type and v are not included in hash
    uint256 getHash() const;

    bool isMint() const;
    bool isSpend() const;
    bool isValidType() const;
	bool isSpatsType() const;

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
	Scalar a, iota;                            // asset type, identifier

	// Serialization depends on the coin type
	ADD_SERIALIZE_METHODS;
	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action) {
		// The type must be valid
		READWRITE(type);
		if (!isValidType()) {
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

		if (isMint() && r_.ciphertext.size() != (1 + AES_BLOCKSIZE) + SCALAR_ENCODING + (1 + params->get_memo_bytes() + 1)) {
			throw std::invalid_argument("Cannot deserialize mint coin due to bad encrypted data");
		}
		if (type == COIN_TYPE_SPEND && r_.ciphertext.size() != 8 + (1 + AES_BLOCKSIZE) + SCALAR_ENCODING + (1 + params->get_memo_bytes() + 1)) {
			throw std::invalid_argument("Cannot deserialize spend coin due to bad encrypted data");
		}

		if (type == COIN_TYPE_SPEND_V2 && r_.ciphertext.size() != 8 + (1 + AES_BLOCKSIZE) + SCALAR_ENCODING * 3 + (1 + params->get_memo_bytes() + 1)) {
			throw std::invalid_argument("Cannot deserialize spend coin due to bad encrypted data");
		}

		if (isMint()) {
			READWRITE(v);
		}

		if (type == COIN_TYPE_MINT_V2) {
            READWRITE(a);
			READWRITE(iota);
		} else {
			if (ser_action.ForRead()) {
                a = Scalar(uint64_t(0));
                iota = Scalar(uint64_t(0));
			}
		}
	}
};

}

#endif
