#include "keys.h"
#include "../hash.h"

namespace spark {

using namespace secp_primitives;

SpendKey::SpendKey(const Params* params) {
	this->params = params;
	this->s1.randomize();
	this->s2.randomize();
	this->r.randomize();
}

SpendKey::SpendKey(const Params* params, const Scalar& r_) {
    this->params = params;
    this->r = r_;
    std::vector<unsigned char> data;
    data.resize(32);
    r.serialize(data.data());
    std::vector<unsigned char> result(CSHA256().OUTPUT_SIZE);

    CHash256 hash256;
    std::string prefix1 = "s1_generation";
    hash256.Write(reinterpret_cast<const unsigned char*>(prefix1.c_str()), prefix1.size());
    hash256.Write(data.data(), data.size());
    hash256.Finalize(&result[0]);
    this->s1.memberFromSeed(&result[0]);

    data.clear();
    result.clear();
    hash256.Reset();
    s1.serialize(data.data());

    std::string prefix2 = "s2_generation";
    hash256.Write(reinterpret_cast<const unsigned char*>(prefix2.c_str()), prefix2.size());
    hash256.Write(data.data(), data.size());
    hash256.Finalize(&result[0]);
    this->s2.memberFromSeed(&result[0]);
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

SpendKey& SpendKey::operator=(const SpendKey& other) {
    this->s1 = other.s1;
    this->s2 = other.s2;
    this->r = other.r;
    return *this;
}

bool SpendKey::operator==(const SpendKey& other) const {
    if (this->s1 != other.s1 ||
    this->s2 != other.s2 ||
    this->r != other.r)
        return false;
    return true;
}

FullViewKey::FullViewKey() {}
FullViewKey::FullViewKey(const Params* params) {
    this->params = params;
}
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

IncomingViewKey::IncomingViewKey(const Params* params) {
    this->params = params;
}

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

Address::Address(const Params* params) {
    this->params = params;
}

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

	// Encode using `bech32m`
	std::string hrp;
	hrp.push_back(ADDRESS_ENCODING_PREFIX);
	hrp.push_back(network);

	std::vector<uint8_t> bit_converted;
	bech32::convertbits(bit_converted, scrambled, 8, 5, true);
	
	return bech32::encode(hrp, bit_converted, bech32::Encoding::BECH32M);
}

// Decode an address (if possible) from a string, returning the network identifier
unsigned char Address::decode(const std::string& str) {
	// Decode using `bech32m`
	bech32::DecodeResult decoded = bech32::decode(str);

	// Check the encoding
	if (decoded.encoding != bech32::Encoding::BECH32M) {
		throw std::invalid_argument("Bad address encoding");
	}

	// Check the encoding prefix
	if (decoded.hrp[0] != ADDRESS_ENCODING_PREFIX) {
		throw std::invalid_argument("Bad address prefix");
	}

	// Get the network identifier
	unsigned char network = decoded.hrp[1];

	// Convert the address components to bytes
	std::vector<uint8_t> scrambled;
	bech32::convertbits(scrambled, decoded.data, 5, 8, false);

	// Assert the proper address size
	if (scrambled.size() != 2 * GroupElement::serialize_size + AES_BLOCKSIZE) {
		throw std::invalid_argument("Bad address size");
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
