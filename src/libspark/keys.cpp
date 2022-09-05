#include "keys.h"
#include "f4grumble.h"

namespace spark {

using namespace secp_primitives;

SpendKey::SpendKey() {}
SpendKey::SpendKey(const Params* params) {
	this->params = params;
	this->s1.randomize();
	this->s2.randomize();
	this->r.randomize();
}

const Params* SpendKey::get_params() const {
	return this->params;
}

const Scalar& SpendKey::get_s1() const {
	return this->s1;
}

const Scalar& SpendKey::get_s2() const {
	return this->s2;
}

const Scalar& SpendKey::get_r() const {
	return this->r;
}

FullViewKey::FullViewKey() {}
FullViewKey::FullViewKey(const SpendKey& spend_key) {
	this->params = spend_key.get_params();
	this->s1 = spend_key.get_s1();
	this->s2 = spend_key.get_s2();
	this->D = this->params->get_G()*spend_key.get_r();
	this->P2 = this->params->get_F()*this->s2 + this->D;
}

const Params* FullViewKey::get_params() const {
	return this->params;
}

const Scalar& FullViewKey::get_s1() const {
	return this->s1;
}

const Scalar& FullViewKey::get_s2() const {
	return this->s2;
}

const GroupElement& FullViewKey::get_D() const {
	return this->D;
}

const GroupElement& FullViewKey::get_P2() const {
	return this->P2;
}

IncomingViewKey::IncomingViewKey() {}
IncomingViewKey::IncomingViewKey(const FullViewKey& full_view_key) {
	this->params = full_view_key.get_params();
	this->s1 = full_view_key.get_s1();
	this->P2 = full_view_key.get_P2();
}

const Params* IncomingViewKey::get_params() const {
	return this->params;
}

const Scalar& IncomingViewKey::get_s1() const {
	return this->s1;
}

const GroupElement& IncomingViewKey::get_P2() const {
	return this->P2;
}

uint64_t IncomingViewKey::get_diversifier(const std::vector<unsigned char>& d) const {
	// Assert proper size
	if (d.size() != AES_BLOCKSIZE) {
		throw std::invalid_argument("Bad encrypted diversifier");
	}

	// Decrypt the diversifier; this is NOT AUTHENTICATED and MUST be externally checked for validity against a claimed address
	std::vector<unsigned char> key = SparkUtils::kdf_diversifier(this->s1);
	uint64_t i = SparkUtils::diversifier_decrypt(key, d);

	return i;
}

Address::Address() {}
Address::Address(const IncomingViewKey& incoming_view_key, const uint64_t i) {
	// Encrypt the diversifier
	std::vector<unsigned char> key = SparkUtils::kdf_diversifier(incoming_view_key.get_s1());
	this->params = incoming_view_key.get_params();
	this->d = SparkUtils::diversifier_encrypt(key, i);
	this->Q1 = SparkUtils::hash_div(this->d)*incoming_view_key.get_s1();
	this->Q2 = this->params->get_F()*SparkUtils::hash_Q2(incoming_view_key.get_s1(), i) + incoming_view_key.get_P2();
}

const Params* Address::get_params() const {
	return this->params;
}

const std::vector<unsigned char>& Address::get_d() const {
	return this->d;
}

const GroupElement& Address::get_Q1() const {
	return this->Q1;
}

const GroupElement& Address::get_Q2() const {
	return this->Q2;
}

// Compute a CRC32-C checksum and convert to hex encoding
std::string Address::get_checksum(const std::string data) {
	uint32_t checksum = leveldb::crc32c::Value(data.data(), data.size());

	// Get bytes
	std::vector<unsigned char> bytes;
	bytes.resize(4);
	bytes[0] = checksum;
	bytes[1] = checksum >> 8;
	bytes[2] = checksum >> 16;
	bytes[3] = checksum >> 24;

	// Hex encode
	std::stringstream result;
	result << std::hex;
	for (const unsigned char b : bytes) {
		result << (b >> 4);
		result << (b & 0xF);
	}
	return result.str();
}

// Encode the address to string, given a network identifier
std::string Address::encode(const unsigned char network) const {
	// Serialize the address components
	std::vector<unsigned char> raw;
	raw.reserve(2 * GroupElement::serialize_size + AES_BLOCKSIZE);

	raw.insert(raw.end(), this->d.begin(), this->d.end());

	std::vector<unsigned char> component;
	component.resize(GroupElement::serialize_size);

	this->get_Q1().serialize(component.data());
	raw.insert(raw.end(), component.begin(), component.end());

	this->get_Q2().serialize(component.data());
	raw.insert(raw.end(), component.begin(), component.end());

	// Apply the scramble encoding and prepend the network byte
	std::vector<unsigned char> scrambled = F4Grumble(network, raw.size()).encode(raw);

	// Encode to hex
	std::stringstream encoded;
	encoded << std::hex;
	encoded << ADDRESS_ENCODING_PREFIX;
	encoded << network;
	for (const unsigned char c : scrambled) {
		encoded << (c >> 4);
		encoded << (c & 0xF);
	}

	// Compute and apply the checksum
	encoded << get_checksum(encoded.str());

	return encoded.str();
}

// Decode an address (if possible) from a string, returning the network identifier
unsigned char Address::decode(const std::string& str) {
	const int CHECKSUM_BYTES = 4;

	// Assert the proper address size
	if (str.size() != (2 * GroupElement::serialize_size + AES_BLOCKSIZE + CHECKSUM_BYTES) * 2 + 2) {
		throw std::invalid_argument("Bad address size");
	}

	// Check the encoding prefix
	if (str[0] != ADDRESS_ENCODING_PREFIX) {
		throw std::invalid_argument("Bad address prefix");
	}

	// Check the checksum
	std::string checksum = str.substr(str.size() - 2 * CHECKSUM_BYTES);
	std::string computed_checksum = get_checksum(str.substr(0, str.size() - 2 * CHECKSUM_BYTES));
	if (computed_checksum != checksum) {
		throw std::invalid_argument("Bad address checksum");
	}

	// Track the network identifier
	unsigned char network = str[1];

	// Decode the scrambled data and checksum from hex
	std::string scrambled_hex = str.substr(2, str.size() - CHECKSUM_BYTES);
	std::vector<unsigned char> scrambled;
	scrambled.resize(2 * GroupElement::serialize_size + AES_BLOCKSIZE);
	for (std::size_t i = 0; i < scrambled.size(); i++) {
		std::string hexs = scrambled_hex.substr(2 * i, 2);

		if (::isxdigit(hexs[0]) && ::isxdigit(hexs[1])) {
            scrambled[i] = strtol(hexs.c_str(), NULL, 16);
        } else {
            throw std::invalid_argument("Bad address encoding");
        }
	}

	// Apply the scramble decoding
	std::vector<unsigned char> raw = F4Grumble(network, scrambled.size()).decode(scrambled);

	// Deserialize the adddress components
	this->d = std::vector<unsigned char>(raw.begin(), raw.begin() + AES_BLOCKSIZE);

	std::vector<unsigned char> component(raw.begin() + AES_BLOCKSIZE, raw.begin() + AES_BLOCKSIZE + GroupElement::serialize_size);
	this->Q1.deserialize(component.data());
	
	component = std::vector<unsigned char>(raw.begin() + AES_BLOCKSIZE + GroupElement::serialize_size, raw.end());
	this->Q2.deserialize(component.data());

	return network;
}

}
