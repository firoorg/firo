#include "coin.h"

namespace spark {

using namespace secp_primitives;

Coin::Coin() {}

Coin::Coin(
	const Params* params,
	const char type,
	const Scalar& k,
	const Address& address,
	const uint64_t v,
	const std::string memo,
	const std::vector<unsigned char> serial_context
) {
	this->params = params;
	this->serial_context = serial_context;

	// Validate the type
	if (type != COIN_TYPE_MINT && type != COIN_TYPE_SPEND) {
		throw std::invalid_argument("Bad coin type");
	}
	this->type = type;


	//
	// Common elements to both coin types
	//

	// Construct the recovery key
	this->K = SparkUtils::hash_div(address.get_d())*SparkUtils::hash_k(k);

	// Construct the serial commitment
	this->S = this->params->get_F()*SparkUtils::hash_ser(k, serial_context) + address.get_Q2();

	// Construct the value commitment
	this->C = this->params->get_G()*Scalar(v) + this->params->get_H()*SparkUtils::hash_val(k);

	// Check the memo validity, and pad if needed
	if (memo.size() > this->params->get_memo_bytes()) {
		throw std::invalid_argument("Memo is too large");
	}
	std::vector<unsigned char> memo_bytes(memo.begin(), memo.end());
	std::vector<unsigned char> padded_memo(memo_bytes);
	padded_memo.resize(this->params->get_memo_bytes());

	//
	// Type-specific elements
	//

	if (this->type == COIN_TYPE_MINT) {
		this->v = v;

		// Encrypt recipient data
		MintCoinRecipientData r;
		r.d = address.get_d();
		r.k = k;
		r.memo = std::string(memo.begin(), memo.end());
		CDataStream r_stream(SER_NETWORK, PROTOCOL_VERSION);
		r_stream << r;
		this->r_ = AEAD::encrypt(address.get_Q1()*SparkUtils::hash_k(k), "Mint coin data", r_stream);
	} else {
		// Encrypt recipient data
		SpendCoinRecipientData r;
		r.v = v;
		r.d = address.get_d();
		r.k = k;
		r.memo = std::string(memo.begin(), memo.end());
		CDataStream r_stream(SER_NETWORK, PROTOCOL_VERSION);
		r_stream << r;
		this->r_ = AEAD::encrypt(address.get_Q1()*SparkUtils::hash_k(k), "Spend coin data", r_stream);
	}
}

// Validate a coin for identification
// NOTE: This assumes the coin has a valid associated range proof, which MUST be separately checked as part of the valid transaction that produced it
bool Coin::validate(
	const IncomingViewKey& incoming_view_key,
	IdentifiedCoinData& data
) {
	// Check recovery key
	if (SparkUtils::hash_div(data.d)*SparkUtils::hash_k(data.k) != this->K) {
		return false;
	}

	// Check value commitment
	if (this->params->get_G()*Scalar(data.v) + this->params->get_H()*SparkUtils::hash_val(data.k) != this->C) {
		return false;
	}

	// Check serial commitment
	data.i = incoming_view_key.get_diversifier(data.d);

	if (this->params->get_F()*(SparkUtils::hash_ser(data.k, this->serial_context) + SparkUtils::hash_Q2(incoming_view_key.get_s1(), data.i)) + incoming_view_key.get_P2() != this->S) {
		return false;
	}

	return true;
}

// Recover a coin
RecoveredCoinData Coin::recover(const FullViewKey& full_view_key, const IdentifiedCoinData& data) {
	RecoveredCoinData recovered_data;
	recovered_data.s = SparkUtils::hash_ser(data.k, this->serial_context) + SparkUtils::hash_Q2(full_view_key.get_s1(), data.i) + full_view_key.get_s2();
	recovered_data.T = (this->params->get_U() + full_view_key.get_D().inverse())*recovered_data.s.inverse();

	return recovered_data;
}

// Identify a coin
IdentifiedCoinData Coin::identify(const IncomingViewKey& incoming_view_key) {
	IdentifiedCoinData data;

	// Deserialization means this process depends on the coin type
	if (this->type == COIN_TYPE_MINT) {
		MintCoinRecipientData r;

		try {
			// Decrypt recipient data
			CDataStream stream = AEAD::decrypt_and_verify(this->K*incoming_view_key.get_s1(), "Mint coin data", this->r_);
			stream >> r;
		} catch (...) {
			throw std::runtime_error("Unable to identify coin");
		}

		data.d = r.d;
		data.v = this->v;
		data.k = r.k;
		data.memo = r.memo;
	} else {
		SpendCoinRecipientData r;

		try {
			// Decrypt recipient data
			CDataStream stream = AEAD::decrypt_and_verify(this->K*incoming_view_key.get_s1(), "Spend coin data", this->r_);
			stream >> r;
		} catch (...) {
			throw std::runtime_error("Unable to identify coin");
		}
			
		data.d = r.d;
		data.v = r.v;
		data.k = r.k;
		data.memo = r.memo;
	}

	// Validate the coin
	if (!validate(incoming_view_key, data)) {
		throw std::runtime_error("Malformed coin");
	}

	return data;
}

}
