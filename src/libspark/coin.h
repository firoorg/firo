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
	std::string memo; // memo

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(d);
		READWRITE(k);
		READWRITE(memo);
    }
};

// Data to be encrypted for the recipient of a coin generated in a spend transaction
struct SpendCoinRecipientData {
	uint64_t v; // value
	std::vector<unsigned char> d; // encrypted diversifier
	Scalar k; // nonce
	std::string memo; // memo

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(v);
        READWRITE(d);
		READWRITE(k);
		READWRITE(memo);
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
		READWRITE(type);
		READWRITE(S);
		READWRITE(K);
		READWRITE(C);
		READWRITE(r_);

		if (type == COIN_TYPE_MINT) {
			READWRITE(v);
		}
	}
};

}

#endif
