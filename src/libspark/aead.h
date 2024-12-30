#ifndef FIRO_SPARK_AEAD_H
#define FIRO_SPARK_AEAD_H
#include <openssl/evp.h>
#include "util.h"

namespace spark {

struct AEADEncryptedData {
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> tag;
	std::vector<unsigned char> key_commitment;

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(ciphertext);

		// Tag must be the correct size
		READWRITE(tag);
		if (tag.size() != AEAD_TAG_SIZE) {
			std::cout << "Bad tag size " << tag.size() << std::endl;
			throw std::invalid_argument("Cannot deserialize AEAD data due to bad tag");
		}

		// Key commitment must be the correct size, which also includes an encoded size
		READWRITE(key_commitment);
		if (key_commitment.size() != AEAD_COMMIT_SIZE) {
			std::cout << "Bad keycom size " << key_commitment.size() << std::endl;
			throw std::invalid_argument("Cannot deserialize AEAD data due to bad key commitment size");
		}
    }
};

class AEAD {
public:
	static AEADEncryptedData encrypt(const GroupElement& prekey, const std::string additional_data, CDataStream& data);
	static CDataStream decrypt_and_verify(const GroupElement& prekey, const std::string associated_data, AEADEncryptedData& data);
};

}

#endif
