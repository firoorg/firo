#include "aead.h"

namespace spark {

// Perform authenticated encryption with ChaCha20-Poly1305
AEADEncryptedData AEAD::encrypt(const std::vector<unsigned char>& key, const std::string additional_data, CDataStream& data) {
	// Check key size
	if (key.size() != AEAD_KEY_SIZE) {
		throw std::invalid_argument("Bad AEAD key size");
	}

	// Set up the result structure
	AEADEncryptedData result;

	// Internal size tracker; we know the size of the data already, and can ignore
	int TEMP;

	// For our application, we can safely use a zero nonce since keys are never reused
	std::vector<unsigned char> iv;
	iv.resize(AEAD_IV_SIZE);

	// Set up the cipher
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key.data(), iv.data());

	// Include the associated data
	std::vector<unsigned char> additional_data_bytes(additional_data.begin(), additional_data.end());
	EVP_EncryptUpdate(ctx, NULL, &TEMP, additional_data_bytes.data(), additional_data_bytes.size());

	// Encrypt the plaintext
	result.ciphertext.resize(data.size());
	EVP_EncryptUpdate(ctx, result.ciphertext.data(), &TEMP, reinterpret_cast<unsigned char *>(data.data()), data.size());
	EVP_EncryptFinal_ex(ctx, NULL, &TEMP);

	// Get the tag
	result.tag.resize(AEAD_TAG_SIZE);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_SIZE, result.tag.data());

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	return result;
}

// Perform authenticated decryption with ChaCha20-Poly1305
CDataStream AEAD::decrypt_and_verify(const std::vector<unsigned char>& key, const std::string additional_data, AEADEncryptedData& data) {
	// Check key size
	if (key.size() != AEAD_KEY_SIZE) {
		throw std::invalid_argument("Bad AEAD key size");
	}

	// Set up the result
	CDataStream result(SER_NETWORK, PROTOCOL_VERSION);

	// Internal size tracker; we know the size of the data already, and can ignore
	int TEMP;

	// For our application, we can safely use a zero nonce since keys are never reused
	std::vector<unsigned char> iv;
	iv.resize(AEAD_IV_SIZE);

	// Set up the cipher
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key.data(), iv.data());

	// Include the associated data
	std::vector<unsigned char> additional_data_bytes(additional_data.begin(), additional_data.end());
	EVP_DecryptUpdate(ctx, NULL, &TEMP, additional_data_bytes.data(), additional_data_bytes.size());

	// Decrypt the ciphertext
	result.resize(data.ciphertext.size());
	EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(result.data()), &TEMP, data.ciphertext.data(), data.ciphertext.size());
	
	// Set the expected tag
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_SIZE, data.tag.data());

	// Decrypt and clean up
	int ret = EVP_DecryptFinal_ex(ctx, NULL, &TEMP);
	EVP_CIPHER_CTX_free(ctx);
	if (ret != 1) {
		throw std::runtime_error("Bad AEAD authentication");
	}

	return result;
}

}
