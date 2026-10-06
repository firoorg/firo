#include "kdf.h"

namespace spark {

// Set up a labeled KDF
KDF::KDF(const std::string label, std::size_t derived_key_size) {
	this->ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(this->ctx, EVP_sha512(), NULL);

	// Write the protocol and mode information
	std::vector<unsigned char> protocol(LABEL_PROTOCOL.begin(), LABEL_PROTOCOL.end());
	EVP_DigestUpdate(this->ctx, protocol.data(), protocol.size());
	EVP_DigestUpdate(this->ctx, &HASH_MODE_KDF, sizeof(HASH_MODE_KDF));

	// Include the label with size
	include_size(label.size());
	std::vector<unsigned char> label_bytes(label.begin(), label.end());
	EVP_DigestUpdate(this->ctx, label_bytes.data(), label_bytes.size());

	// Embed and set the derived key size
	if (cmp::greater(derived_key_size, EVP_MD_size(EVP_sha512()))) {
		throw std::invalid_argument("Requested KDF size is too large");
	}
	include_size(derived_key_size);
	this->derived_key_size = derived_key_size;
}

// Clean up
KDF::~KDF() {
	EVP_MD_CTX_free(this->ctx);
}

// Include serialized data in the KDF
void KDF::include(CDataStream& data) {
	include_size(data.size());
	EVP_DigestUpdate(this->ctx, reinterpret_cast<unsigned char *>(data.data()), data.size());
}

// Finalize the KDF with arbitrary size
std::vector<unsigned char> KDF::finalize() {
	std::vector<unsigned char> result;
	result.resize(EVP_MD_size(EVP_sha512()));

	unsigned int TEMP;
	EVP_DigestFinal_ex(this->ctx, result.data(), &TEMP);
	result.resize(this->derived_key_size);

	return result;
}

// Include a serialized size in the KDF
void KDF::include_size(std::size_t size) {
	CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
	stream << (uint64_t)size;
	EVP_DigestUpdate(this->ctx, reinterpret_cast<unsigned char *>(stream.data()), stream.size());
}

}